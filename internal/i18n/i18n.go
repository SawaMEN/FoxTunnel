// Package i18n localizes operator-facing text; wire values and JSON keys stay stable.
package i18n

import (
	"fmt"
	"sync/atomic"
)

var russian atomic.Bool

// SetLanguage is called once at CLI startup. Library callers keep English by default.
func SetLanguage(language string) error {
	switch language {
	case "ru":
		russian.Store(true)
	case "en":
		russian.Store(false)
	default:
		return fmt.Errorf(Text("unknown language %q (choose ru or en)"), language)
	}
	return nil
}
func Text(english string) string {
	if russian.Load() {
		if value, ok := translations[english]; ok {
			return value
		}
	}
	return english
}

type messageError string

func (e messageError) Error() string { return Text(string(e)) }
func Error(english string) error     { return messageError(english) }

var translations = map[string]string{
	"QUIC client: quic-go or experimental neqo (h3-post only)":       "Клиент QUIC: quic-go или экспериментальный neqo (только h3-post)",
	"Neqo handshake fallback: none or h2 (before sending a request)": "При недоступности Neqo: none или h2 (до отправки запроса)",
	"Neqo handshake budget (default 2s; 100ms through 10s)":          "Срок рукопожатия Neqo (по умолчанию 2с; от 100мс до 10с)",

	"TLS client profile: default or experimental firefox-158 (NSS 3.130)":  "Профиль TLS-клиента: default или экспериментальный firefox-158 (NSS 3.130)",
	"unknown TLS client profile (choose default or firefox-158)":           "Неизвестный профиль TLS-клиента (выберите default или firefox-158)",
	"TLS client profile requires NSS":                                      "Профиль TLS-клиента требует NSS",
	"firefox-158 TLS client profile requires the pinned NSS 3.130 runtime": "Профиль TLS firefox-158 требует закреплённые библиотеки NSS 3.130",

	"print machine-readable build information":                       "Вывести сведения о сборке в JSON",
	"HTTP/2 receive profile: default or experimental firefox-158":    "Профиль приёма HTTP/2: default или экспериментальный firefox-158",
	"unknown HTTP/2 receive profile (choose default or firefox-158)": "Неизвестный профиль приёма HTTP/2 (выберите default или firefox-158)",
	"HTTP/2 receive profile requires an H2 or XHTTP transport":       "Профиль приёма HTTP/2 требует транспорт H2 или XHTTP",

	"XHTTP path prefix (setup generates a random route by default)": "Префикс пути XHTTP (setup по умолчанию создаёт случайный маршрут)",
	"invalid XHTTP path or Host":                                    "Недопустимый путь или HTTP Host для XHTTP",
	"XHTTP settings require an XHTTP transport":                     "Настройки XHTTP требуют выбора транспорта XHTTP",
	"XHTTP path prefix (default: built-in route)":                   "Префикс пути XHTTP (по умолчанию встроенный маршрут)",
	"outer XHTTP Host override (does not change TLS SNI)":           "HTTP Host внешнего XHTTP-соединения (не меняет TLS SNI)",
	"HTTP/3 requires Go QUIC TLS; NSS cannot be selected":           "HTTP/3 использует Go QUIC TLS; NSS для него недоступен",
	"optional native HTTP/3 UDP listening address":                  "Необязательный адрес UDP для встроенного HTTP/3",
	"bond requires HTTP/2 or HTTP/3":                                "Объединение нод требует HTTP/2 или HTTP/3",

	"native transport: h2-connect, h2-post, h3-post, wss, xhttp-stream-one, xhttp-stream-up or xhttp-packet-up (no external proxy)": "Встроенный транспорт: h2-connect, h2-post, h3-post, wss, xhttp-stream-one, xhttp-stream-up или xhttp-packet-up (без внешнего прокси)",
	"unknown native transport (choose h2-connect, h2-post, h3-post, wss, xhttp-stream-one, xhttp-stream-up or xhttp-packet-up)":     "Неизвестный встроенный транспорт (выберите h2-connect, h2-post, h3-post, wss, xhttp-stream-one, xhttp-stream-up или xhttp-packet-up)",
	"configure transport before enabling bond": "Настройте транспорт до включения объединения нод",
	"native WebSocket handshake rejected":      "Отклонено согласование встроенного WebSocket",
	"unsupported NSS ALPN":                     "Неподдерживаемый ALPN для NSS",

	"unsupported NSS certificate callback (use VerifyConnection)":                            "Неподдерживаемая проверка сертификата NSS (используйте VerifyConnection)",
	"public website overlaps private configuration":                                          "Каталог публичного сайта содержит закрытые настройки или ключ сервера",
	"invalid TLS identity settings":                                                          "Некорректные настройки SNI или публичного ключа сервера",
	"TLS verification cannot be disabled":                                                    "Проверку TLS нельзя отключать",
	"configure TLS before enabling bond":                                                     "Настройте TLS до включения объединения путей",
	"verified TLS server name (default: URL hostname)":                                       "Проверяемое имя TLS/SNI (по умолчанию — имя из URL)",
	"additional server SPKI pin: sha256/base64":                                              "Дополнительный отпечаток публичного ключа SPKI: sha256/base64",
	"encryption: tls13 (secure negotiation only)":                                            "Шифрование: tls13 (автоматическое безопасное согласование)",
	"unsupported encryption (use tls13)":                                                     "Неподдерживаемое шифрование (используйте tls13)",
	"new private configuration directory (must not exist)":                                   "Новый закрытый каталог конфигурации (не должен существовать)",
	"join a main node using its connection file":                                             "Присоединить входную ноду по файлу подключения главной ноды",
	"private server configuration JSON":                                                      "Закрытый JSON-файл конфигурации сервера",
	"public node identity JSON to add or update":                                             "JSON с публичными параметрами добавляемой или обновляемой ноды",
	"configuration created: server.json, connection.txt and node.json (secrets not printed)": "Созданы server.json, connection.txt и node.json (секреты не выводятся)",
	"cluster updated; new sessions receive the change on refresh":                            "Кластер обновлён; новые сессии получат изменения при обновлении состава",
	"verified TLS server name for the common exit":                                           "Проверяемое имя TLS/SNI главной ноды",
	"additional SPKI pin for the common exit":                                                "Дополнительный отпечаток публичного ключа главной ноды",
	"maximum accepted sockets including incomplete TLS handshakes":                           "Максимум принятых сокетов, включая незавершённые TLS-рукопожатия",
	"maximum local SOCKS sockets including incomplete handshakes":                            "Максимум локальных SOCKS-сокетов, включая незавершённые подключения",
	"server config cannot be combined with server-setting flags":                             "Серверный файл конфигурации нельзя смешивать с флагами настройки сервера",
	"invalid connection limit":                                                               "Некорректный лимит подключений",
	"invalid server configuration":                                                           "Некорректная конфигурация сервера",
	"setup failed; verify certificates, names and output directory":                          "Не удалось создать конфигурацию: проверьте сертификаты, имена и новый каталог вывода",
	"cluster JSON file served by the common exit (requires --bond-hub)":                      "JSON-файл состава кластера на главной ноде (требуется --bond-hub)",
	"obtain trusted bond nodes and capacity weights from the main HTTPS node":                "Получить доверенные ноды и веса мощности с главной HTTPS-ноды",
	"cluster configuration requires --bond-hub":                                              "Состав кластера можно выдавать только с главной ноды --bond-hub",
	"cluster discovery requires --bond":                                                      "Получение состава кластера требует --bond",
	"invalid cluster configuration":                                                          "Некорректная конфигурация кластера",
	"cluster discovery failed":                                                               "Не удалось получить состав кластера с главной ноды",
	"invalid vetroff connection link":                                                        "Некорректная ссылка подключения vetroff://",
	"vetroff connection link (prefer --link-file for secrets)":                               "Ссылка vetroff:// (для секретов предпочтительнее --link-file)",
	"read vetroff connection link from file or - for stdin":                                  "Прочитать ссылку vetroff:// из файла или - для stdin",
	"choose either --link or --link-file":                                                    "Выберите только --link или --link-file",
	"connection link cannot be combined with connection-setting flags":                       "Ссылку нельзя сочетать с параметрами настройки подключения",
	"cannot read connection link file":                                                       "Не удалось прочитать файл ссылки подключения",
	"usage: foxtunnel <version|setup|server|client|share|cluster-add> [flags] (credentials: environment or vetroff link)": "Использование: foxtunnel <version|setup|server|client|share|cluster-add> [параметры] (учётные данные: окружение или ссылка vetroff://)",

	"experimental persistent bond channels and small-write batching (requires --bond)": "Экспериментальные постоянные bond-каналы и объединение мелких записей (нужен --bond)",
	"bond lanes require --bond":                                   "Для постоянных bond-каналов нужен --bond",
	"bond pipeline must be auto, 4 or 8":                          "Глубина конвейера объединения: auto, 4 или 8",
	"bond pipeline: auto, 4 or 8 (higher depth uses more memory)": "Конвейер объединения: auto, 4 или 8 (большая глубина требует больше памяти)",
	"bond attempt timeout must be at least 100ms":                 "В режиме объединения время попытки должно быть не меньше 100ms",
	"invalid bond hub identity":                                   "Некорректный идентификатор общего выхода",
	"bond requires HTTP/2":                                        "Объединение путей требует HTTP/2",
	"oversized bond response":                                     "Превышен размер ответа объединения путей",
	"bond HTTP status %d":                                         "HTTP-статус объединения путей: %d",
	"bond requires two to eight trusted nodes":                    "Для объединения нужны от двух до восьми доверенных нод",

	"bond requires at least two trusted nodes":                         "Для объединения нужны хотя бы две доверенные ноды",
	"bond and initial-v1 padding cannot be combined":                   "Объединение путей нельзя сочетать с дополнением initial-v1",
	"enable experimental common exit for bonded streams":               "Включить экспериментальный общий выход для объединённых потоков",
	"trusted HTTPS common exit; run this server as a bond relay":       "Доверенный HTTPS-выход; запустить сервер как входную ноду объединения",
	"additional trusted PEM for the common exit":                       "Дополнительный доверенный PEM-сертификат общего выхода",
	"choose either --bond-hub or --bond-upstream":                      "Выберите только --bond-hub или --bond-upstream",
	"experimental multi-node stream bonding; nodes must share one hub": "Экспериментальное объединение путей; ноды должны использовать общий выход",

	"set FOXTUNNEL_USER and FOXTUNNEL_PASSWORD (nonempty)":                                         "Задайте непустые FOXTUNNEL_USER и FOXTUNNEL_PASSWORD",
	"HTTPS listening address":                                                                      "Адрес HTTPS-сервера",
	"TLS certificate PEM":                                                                          "Сертификат TLS в формате PEM",
	"TLS private key PEM":                                                                          "Закрытый ключ TLS в формате PEM",
	"enable experimental negotiated initial-record padding":                                        "Включить экспериментальное согласуемое дополнение первых записей",
	"maximum active authenticated tunnels, including destination dialing":                          "Максимум туннелей с авторизацией, включая подключение к назначению",
	"public website directory for ordinary requests and rejected probes":                           "Каталог публичного сайта для обычных запросов и отклонённых проб",
	"permit private/loopback destination IPs (unsafe on public deployments)":                       "Разрешить частные и локальные IP назначения (опасно на публичном сервере)",
	"--max-tunnels must be positive":                                                               "--max-tunnels должен быть больше нуля",
	"--cert and --key are required":                                                                "Обязательны --cert и --key",
	"HTTPS CONNECT listener: %s":                                                                   "HTTPS CONNECT слушает: %s",
	"local SOCKS5 listening address":                                                               "Адрес локального SOCKS5",
	"remote HTTPS proxy URL":                                                                       "URL удалённого HTTPS-прокси",
	"explicit trusted HTTPS proxy fallback (repeat up to seven times)":                             "Дополнительный доверенный HTTPS-прокси (до семи повторений)",
	"new-stream scheduling: failover, round-robin, least-active":                                   "Распределение новых потоков: failover, round-robin, least-active",
	"setup time per endpoint when fallbacks are configured":                                        "Время подключения к одному серверу при наличии дополнительных серверов",
	"require experimental initial-record padding (server must enable it)":                          "Требовать дополнение первых записей (нужно включить и на сервере)",
	"TLS backend: go or experimental nss (requires -tags nss build)":                               "Реализация TLS: go или экспериментальная nss (сборка с -tags nss)",
	"maximum CONNECT setup time (does not limit stream lifetime)":                                  "Общее время установки CONNECT (не ограничивает жизнь потока)",
	"additional trusted certificate PEM":                                                           "Дополнительный доверенный сертификат PEM",
	"--fallback-attempt-timeout must be positive":                                                  "--fallback-attempt-timeout должен быть больше нуля",
	"--connect-timeout must be positive":                                                           "--connect-timeout должен быть больше нуля",
	"SOCKS5 listener: %s":                                                                          "SOCKS5 слушает: %s",
	"usage: foxtunnel <server|client> [flags] (FOXTUNNEL_USER and FOXTUNNEL_PASSWORD must be set)": "Использование: foxtunnel <server|client> [параметры] (задайте FOXTUNNEL_USER и FOXTUNNEL_PASSWORD)",
	"listen on loopback for one ClientHello (closes before TLS completes)":                         "Принять один ClientHello на локальном IP (без завершения TLS)",
	"capture the current Go TLS ClientHello without using network":                                 "Получить текущий ClientHello Go TLS без сетевого подключения",
	"read fingerprint from JSON file":                                                              "Прочитать отпечаток из JSON-файла",
	"write JSON to file (otherwise stdout)":                                                        "Записать JSON в файл (иначе — стандартный вывод)",
	"reference fingerprint JSON for a detailed comparison":                                         "Эталонный JSON-отпечаток для подробного сравнения",
	"return nonzero if any compared field differs":                                                 "Вернуть ненулевой код при различии сравниваемых полей",
	"choose exactly one of --listen, --sample-go, --input":                                         "Выберите ровно один режим: --listen, --sample-go или --input",
	"--listen must bind to an explicit loopback IP":                                                "В --listen укажите явный локальный IP обратной петли",
	"capture listening on":                                                                         "Ожидание ClientHello на",
	"(one handshake; TLS failure on browser is expected)":                                          "(одно рукопожатие; ошибка TLS в браузере ожидаема)",
	"DIFF":        "РАЗЛИЧИЕ",
	": reference": ": эталон",
	"candidate":   "кандидат",
	"JA3: equal (not proof of browser equivalence)": "JA3: совпадает (это не доказывает эквивалентность браузеру)",
	"JA3: different":      "JA3: различается",
	"fingerprints differ": "Отпечатки различаются",
	"nonempty credentials and a username without colon are required": "Нужны непустые учётные данные; имя пользователя не должно содержать двоеточие",
	"system CA store: %w":                       "Системное хранилище CA: %w",
	"CA file contains no PEM certificates":      "В файле CA нет сертификатов PEM",
	"unknown TLS backend %q (choose go or nss)": "Неизвестная реализация TLS %q (выберите go или nss)",
	"unsupported SOCKS greeting":                "Неподдерживаемое приветствие SOCKS",
	"SOCKS no-auth method unavailable":          "Метод SOCKS без аутентификации недоступен",
	"only SOCKS CONNECT is supported":           "Поддерживается только SOCKS CONNECT",
	"empty hostname":                            "Пустое имя узла",
	"unsupported SOCKS address type":            "Неподдерживаемый тип адреса SOCKS",
	"invalid destination":                       "Некорректный адрес назначения",
	"missing host or port":                      "Не указан узел или порт",
	"invalid port":                              "Некорректный порт",
	"no permitted destination addresses":        "Нет разрешённых адресов назначения",
	"proxy must negotiate h2 ALPN":              "Прокси должен согласовать h2 через ALPN",
	"server must be an https://host[:port] URL": "Сервер должен иметь URL https://узел[:порт]",
	"at most %d fallback servers are allowed":   "Допускается не более %d дополнительных серверов",
	"duplicate proxy origin":                    "Адрес прокси повторяется",
	"CONNECT rejected (HTTP/%d status %d)":      "CONNECT отклонён (HTTP/%d, статус %d)",
	"CONNECT padding negotiation failed":        "Не удалось согласовать дополнение записей CONNECT",
	"unknown balance mode %q":                   "Неизвестный режим распределения %q",
	"no destination addresses":                  "Нет адресов назначения",
	"unsupported padding mode":                  "Неподдерживаемый режим дополнения записей",
	"invalid underlying write count":            "Некорректное число записанных байтов",
	"invalid padding record length":             "Некорректная длина записи с дополнением",
	"NSS backend unavailable: build on Linux with CGO_ENABLED=1 and -tags nss (NSS/NSPR development packages required)": "NSS недоступен: соберите на Linux с CGO_ENABLED=1 и -tags nss (нужны пакеты разработки NSS/NSPR)",
	"NSS initialization failed: %d":                       "Ошибка инициализации NSS: %d",
	"NSS connection settings: %d":                         "Ошибка настройки соединения NSS: %d",
	"NSS handshake/ALPN failed: %d":                       "Ошибка рукопожатия NSS/ALPN: %d",
	"NSS read failed: %d":                                 "Ошибка чтения NSS: %d",
	"NSS write failed: %d":                                "Ошибка записи NSS: %d",
	"NSS peer provided no certificate":                    "Сервер NSS не предоставил сертификат",
	"TLS record header: %w":                               "Заголовок записи TLS: %w",
	"expected TLS handshake record":                       "Ожидалась запись рукопожатия TLS",
	"invalid TLS record length":                           "Некорректная длина записи TLS",
	"ClientHello exceeds 64 KiB":                          "ClientHello превышает 64 КиБ",
	"TLS record body: %w":                                 "Тело записи TLS: %w",
	"first handshake message is not ClientHello":          "Первое сообщение рукопожатия не является ClientHello",
	"odd 16-bit vector length":                            "Нечётная длина 16-битного вектора",
	"invalid ClientHello frame":                           "Некорректная запись ClientHello",
	"invalid session id":                                  "Некорректный идентификатор сессии",
	"invalid cipher suites":                               "Некорректные наборы шифров",
	"invalid compression methods":                         "Некорректные методы сжатия",
	"missing extensions":                                  "Отсутствуют расширения",
	"invalid extension block":                             "Некорректный блок расширений",
	"bad supported-groups/signature-algorithms extension": "Некорректное расширение supported-groups/signature-algorithms",
	"bad EC point formats extension":                      "Некорректное расширение форматов точек EC",
	"bad ALPN extension":                                  "Некорректное расширение ALPN",
	"bad ALPN protocol":                                   "Некорректный протокол ALPN",
	"bad supported versions":                              "Некорректные поддерживаемые версии",
	"bad key shares":                                      "Некорректный список key share",
	"bad key share":                                       "Некорректный key share",
	"Language: ru (default), en":                          "Язык: ru (по умолчанию), en",
	"Usage:":                                              "Использование:",
	"Options:":                                            "Параметры:",
	"default":                                             "по умолчанию",
	"unknown language %q (choose ru or en)":               "Неизвестный язык %q (выберите ru или en)",
	"--lang requires ru or en":                            "--lang требует значения ru или en",
	"invalid arguments: %v":                               "Некорректные параметры: %v",
}
