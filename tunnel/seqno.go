package tunnel

func (obj *SeqnoWindow) shiftRightInPlace(diff uint32) {
	totalBits := uint32(len(obj.window) * 64)
	if diff >= totalBits {
		for i := range obj.window {
			obj.window[i] = 0
		}
		return
	}

	wordShift := int(diff / 64)
	bitShift := diff % 64

	for i := len(obj.window) - 1; i >= 0; i-- {
		srcIndex := i - wordShift
		if srcIndex < 0 {
			obj.window[i] = 0
			continue
		}

		newVal := obj.window[srcIndex] >> bitShift
		if bitShift > 0 && srcIndex > 0 {
			newVal |= obj.window[srcIndex-1] << (64 - bitShift)
		}
		obj.window[i] = newVal
	}
}

func (s *Section) checkSeqno(seqno uint32, cached bool) bool {
	obj := &s.seqno
	if cached {
		obj = &s.seqnoCached
	}

	totalBits := uint32(len(obj.window) * 64)

	obj.mx.Lock()
	defer obj.mx.Unlock()

	// overflow, reset
	if seqno < obj.latest && (obj.latest-seqno) > (1<<31) {
		obj.latest = seqno
		for i := range obj.window {
			obj.window[i] = 0
		}
		obj.window[0] = 1 << 63
		return true
	}

	if seqno > obj.latest {
		diff := seqno - obj.latest
		if diff >= totalBits {
			for i := range obj.window {
				obj.window[i] = 0
			}
			obj.window[0] = 1 << 63
		} else {
			obj.shiftRightInPlace(diff)
			obj.window[0] |= 1 << 63
		}
		obj.latest = seqno
		return true
	}

	if seqno == obj.latest {
		// repeat
		return false
	}

	diff := obj.latest - seqno
	if diff >= totalBits {
		// too old
		return false
	}

	wordIndex := diff / 64
	bitIndex := 63 - diff%64

	if (obj.window[wordIndex]>>bitIndex)&1 != 0 {
		// repeat
		return false
	}

	obj.window[wordIndex] |= 1 << bitIndex
	return true
}

/*
func (s *Section) checkSeqnoFastShort(seqno uint32) bool {
	// handle overflow, reset
	if seqno < obj.latest && (obj.latest-seqno) > (1<<31) {
		obj.latest = seqno
		obj.window[0] = 1 << 63
		return true
	}

	if seqno > obj.latest {
		diff := seqno - obj.latest
		if diff >= 64 {
			obj.window[0] = 1 << 63
		} else {
			obj.window[0] = (obj.window[0] >> diff) | (1 << 63)
		}
		obj.latest = seqno
		return true
	}

	if seqno == obj.latest {
		return false
	}

	diff := obj.latest - seqno
	if diff >= 64 {
		return false
	}

	if (obj.window[0]>>(63-diff))&1 != 0 {
		return false
	}

	obj.window[0] |= 1 << (63 - diff)
	return true
}
*/
