package tunnel

func (s *Section) shiftRightInPlace(diff uint32) {
	totalBits := uint32(len(s.seqnoWindow) * 64)
	if diff >= totalBits {
		for i := range s.seqnoWindow {
			s.seqnoWindow[i] = 0
		}
		return
	}

	wordShift := int(diff / 64)
	bitShift := diff % 64

	for i := len(s.seqnoWindow) - 1; i >= 0; i-- {
		srcIndex := i - wordShift
		if srcIndex < 0 {
			s.seqnoWindow[i] = 0
			continue
		}

		newVal := s.seqnoWindow[srcIndex] >> bitShift
		if bitShift > 0 && srcIndex > 0 {
			newVal |= s.seqnoWindow[srcIndex-1] << (64 - bitShift)
		}
		s.seqnoWindow[i] = newVal
	}
}

func (s *Section) checkSeqno(seqno uint32) bool {
	totalBits := uint32(len(s.seqnoWindow) * 64)

	s.seqnoMx.Lock()
	defer s.seqnoMx.Unlock()

	// overflow, reset
	if seqno < s.lastSeqno && (s.lastSeqno-seqno) > (1<<31) {
		s.lastSeqno = seqno
		for i := range s.seqnoWindow {
			s.seqnoWindow[i] = 0
		}
		s.seqnoWindow[0] = 1 << 63
		return true
	}

	if seqno > s.lastSeqno {
		diff := seqno - s.lastSeqno
		if diff >= totalBits {
			for i := range s.seqnoWindow {
				s.seqnoWindow[i] = 0
			}
			s.seqnoWindow[0] = 1 << 63
		} else {
			s.shiftRightInPlace(diff)
			s.seqnoWindow[0] |= 1 << 63
		}
		s.lastSeqno = seqno
		return true
	}

	if seqno == s.lastSeqno {
		// repeat
		return false
	}

	diff := s.lastSeqno - seqno
	if diff >= totalBits {
		// too old
		return false
	}

	wordIndex := diff / 64
	bitIndex := 63 - diff%64

	if (s.seqnoWindow[wordIndex]>>bitIndex)&1 != 0 {
		// repeat
		return false
	}

	s.seqnoWindow[wordIndex] |= 1 << bitIndex
	return true
}

/*
func (s *Section) checkSeqnoFastShort(seqno uint32) bool {
	// handle overflow, reset
	if seqno < s.lastSeqno && (s.lastSeqno-seqno) > (1<<31) {
		s.lastSeqno = seqno
		s.seqnoWindow[0] = 1 << 63
		return true
	}

	if seqno > s.lastSeqno {
		diff := seqno - s.lastSeqno
		if diff >= 64 {
			s.seqnoWindow[0] = 1 << 63
		} else {
			s.seqnoWindow[0] = (s.seqnoWindow[0] >> diff) | (1 << 63)
		}
		s.lastSeqno = seqno
		return true
	}

	if seqno == s.lastSeqno {
		return false
	}

	diff := s.lastSeqno - seqno
	if diff >= 64 {
		return false
	}

	if (s.seqnoWindow[0]>>(63-diff))&1 != 0 {
		return false
	}

	s.seqnoWindow[0] |= 1 << (63 - diff)
	return true
}
*/
