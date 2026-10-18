//go:build nss && cgo && linux

#include "bridge.h"
#include <stdlib.h>
#include <string.h>
#include <nss.h>
#include <ssl.h>
#include <sslproto.h>
#include <cert.h>
#include <prerror.h>
#include <prnetdb.h>
#include <secerr.h>

/* These callbacks borrow C buffers only for the duration of the call. The
 * descriptor stores an opaque cgo handle, never a pointer into the Go heap. */
extern int ft_go_read(uintptr_t handle, void *buffer, int length);
extern int ft_go_write(uintptr_t handle, void *buffer, int length);
extern int ft_go_cert(uintptr_t handle, void *buffer, int length);
extern int ft_go_verify(uintptr_t handle);

typedef struct { uintptr_t handle; PRNetAddr local,remote; } Layer;
static PRIOMethods methods;
static PRDescIdentity identity;
static Layer *layer(PRFileDesc *fd) { return (Layer *)fd->secret; }
static PRStatus close_layer(PRFileDesc *fd) {
 free(fd->secret); fd->secret=NULL; fd->dtor(fd); return PR_SUCCESS;
}
static PRInt32 receive(PRFileDesc *fd, void *buffer, PRInt32 length, PRIntn flags, PRIntervalTime timeout) {
 (void)timeout;
 if(flags!=0) {PR_SetError(PR_INVALID_ARGUMENT_ERROR,0);return -1;}
 int n=ft_go_read(layer(fd)->handle,buffer,length);
 if(n<0) PR_SetError(PR_IO_ERROR,0);
 return n;
}
static PRInt32 send_data(PRFileDesc *fd, const void *buffer, PRInt32 length, PRIntn flags, PRIntervalTime timeout) {
 (void)timeout;
 if(flags!=0) {PR_SetError(PR_INVALID_ARGUMENT_ERROR,0);return -1;}
 int n=ft_go_write(layer(fd)->handle,(void *)buffer,length);
 if(n<0) PR_SetError(PR_IO_ERROR,0);
 return n;
}
static PRInt32 read_data(PRFileDesc *fd,void *p,PRInt32 n){return receive(fd,p,n,0,PR_INTERVAL_NO_TIMEOUT);}
static PRInt32 write_data(PRFileDesc *fd,const void *p,PRInt32 n){return send_data(fd,p,n,0,PR_INTERVAL_NO_TIMEOUT);}
static PRStatus get_local(PRFileDesc *fd, PRNetAddr *addr){*addr=layer(fd)->local;return PR_SUCCESS;}
static PRStatus get_remote(PRFileDesc *fd, PRNetAddr *addr){*addr=layer(fd)->remote;return PR_SUCCESS;}
static PRStatus get_option(PRFileDesc *fd, PRSocketOptionData *data) {
 (void)fd;
 if(data->option==PR_SockOpt_Nonblocking){data->value.non_blocking=PR_FALSE;return PR_SUCCESS;}
 if(data->option==PR_SockOpt_NoDelay){data->value.no_delay=PR_TRUE;return PR_SUCCESS;}
 PR_SetError(PR_OPERATION_NOT_SUPPORTED_ERROR,0);return PR_FAILURE;
}
static PRStatus set_option(PRFileDesc *fd,const PRSocketOptionData *data){
 (void)fd;
 if(data->option==PR_SockOpt_Nonblocking&&!data->value.non_blocking)return PR_SUCCESS;
 if(data->option==PR_SockOpt_NoDelay&&data->value.no_delay)return PR_SUCCESS;
 PR_SetError(PR_OPERATION_NOT_SUPPORTED_ERROR,0);return PR_FAILURE;
}
static SECStatus authenticate(void *arg,PRFileDesc *fd,PRBool checksig,PRBool server){
 (void)checksig;
 if(server) return SECFailure;
 CERTCertList *chain=SSL_PeerCertificateChain(fd);
 if(!chain)return SECFailure;
 int count=0,ok=1;
 for(CERTCertListNode *node=CERT_LIST_HEAD(chain);!CERT_LIST_END(node,chain);node=CERT_LIST_NEXT(node)){
  if(++count>16 || node->cert->derCert.len>(1U<<20) ||
     !ft_go_cert((uintptr_t)arg,node->cert->derCert.data,(int)node->cert->derCert.len)){ok=0;break;}
 }
 CERT_DestroyCertList(chain);
 if(!ok||!ft_go_verify((uintptr_t)arg)){PR_SetError(SEC_ERROR_UNTRUSTED_CERT,0);return SECFailure;}
 return SECSuccess;
}
int ft_init(void){
 if(NSS_NoDB_Init(NULL)!=SECSuccess)return PR_GetError();
 if(NSS_SetDomesticPolicy()!=SECSuccess)return PR_GetError();
 identity=PR_GetUniqueIdentity("foxtunnel-go-io");
 methods=*PR_GetDefaultIOMethods();methods.file_type=PR_DESC_SOCKET_TCP;
 methods.close=close_layer;methods.read=read_data;methods.write=write_data;
 methods.recv=receive;methods.send=send_data;
 methods.getsockname=get_local;methods.getpeername=get_remote;
 methods.getsocketoption=get_option;methods.setsocketoption=set_option;
 return 0;
}
PRFileDesc *ft_new(uintptr_t handle,const char *name,const char *local,const char *remote,const char *protocol,int *error){
 PRFileDesc *fd=PR_CreateIOLayerStub(identity,&methods);
 if(!fd){*error=PR_GetError();return NULL;}
 Layer *data=calloc(1,sizeof(Layer));
 if(!data){fd->dtor(fd);*error=PR_OUT_OF_MEMORY_ERROR;return NULL;}
 data->handle=handle;fd->secret=(PRFilePrivate *)data;
 if(PR_StringToNetAddr(local,&data->local)!=PR_SUCCESS || PR_StringToNetAddr(remote,&data->remote)!=PR_SUCCESS){*error=PR_GetError();PR_Close(fd);return NULL;}
 PRFileDesc *secure=SSL_ImportFD(NULL,fd);
 if(!secure){*error=PR_GetError();PR_Close(fd);return NULL;}
 fd=secure;
 SSLVersionRange range={SSL_LIBRARY_VERSION_TLS_1_3,SSL_LIBRARY_VERSION_TLS_1_3};
 unsigned char alpn[10]; size_t protocol_len=strlen(protocol);
 if(protocol_len!=2 && protocol_len!=8){*error=PR_PROTOCOL_NOT_SUPPORTED_ERROR;PR_Close(fd);return NULL;}
 alpn[0]=(unsigned char)protocol_len;memcpy(alpn+1,protocol,protocol_len);
 if(SSL_OptionSet(fd,SSL_SECURITY,PR_TRUE)!=SECSuccess ||
    SSL_OptionSet(fd,SSL_HANDSHAKE_AS_CLIENT,PR_TRUE)!=SECSuccess ||
    SSL_OptionSet(fd,SSL_NO_CACHE,PR_TRUE)!=SECSuccess ||
    SSL_OptionSet(fd,SSL_ENABLE_SESSION_TICKETS,PR_FALSE)!=SECSuccess ||
    SSL_VersionRangeSet(fd,&range)!=SECSuccess ||
    SSL_SetURL(fd,name)!=SECSuccess ||
    SSL_SetNextProtoNego(fd,alpn,(unsigned int)protocol_len+1)!=SECSuccess ||
    SSL_AuthCertificateHook(fd,authenticate,(void *)handle)!=SECSuccess ||
    SSL_ResetHandshake(fd,PR_FALSE)!=SECSuccess){*error=PR_GetError();PR_Close(fd);return NULL;}
 return fd;
}
int ft_handshake(PRFileDesc *fd,const char *protocol,int *error){
 if(SSL_ForceHandshake(fd)!=SECSuccess){*error=PR_GetError();return -1;}
 SSLNextProtoState state;unsigned char proto[16];unsigned int length=0;
 if(SSL_GetNextProto(fd,&state,proto,&length,sizeof(proto))!=SECSuccess ||
    state!=SSL_NEXT_PROTO_SELECTED || length!=strlen(protocol) || memcmp(proto,protocol,length)!=0){*error=PR_PROTOCOL_NOT_SUPPORTED_ERROR;return -1;}
 return 0;
}
int ft_read(PRFileDesc *fd,void *buffer,int length,int *error){int n=PR_Read(fd,buffer,length);if(n<0)*error=PR_GetError();return n;}
int ft_write(PRFileDesc *fd,const void *buffer,int length,int *error){int n=PR_Write(fd,buffer,length);if(n<0)*error=PR_GetError();return n;}
void ft_close(PRFileDesc *fd){PR_Close(fd);}
const char *ft_version(void){return NSS_GetVersion();}
