package bond

import "time"

const coalesceDelay = time.Millisecond

func (s *Stream) coalesce(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if len(s.small) == 0 && len(p) >= chunkSize {
			n, err := s.writeBlocks(p)
			return written + n, err
		}
		if s.small == nil {
			s.small = make([]byte, 0, chunkSize)
		}
		n := min(len(p), chunkSize-len(s.small))
		s.small = append(s.small, p[:n]...)
		p = p[n:]
		written += n
		if len(s.small) == chunkSize {
			if err := s.flushSmall(); err != nil {
				return written, err
			}
		} else if s.flushTimer == nil {
			s.flushTimer = time.AfterFunc(coalesceDelay, func() {
				s.writeMu.Lock()
				defer s.writeMu.Unlock()
				if s.ctx.Err() == nil {
					if s.flushSmall() != nil {
						s.cancel()
					}
				}
			})
		}
	}
	return written, nil
}
func (s *Stream) flushSmall() error {
	if s.flushTimer != nil {
		s.flushTimer.Stop()
		s.flushTimer = nil
	}
	if len(s.small) == 0 {
		return nil
	}
	_, err := s.writeBlocks(s.small)
	s.small = s.small[:0]
	return err
}
