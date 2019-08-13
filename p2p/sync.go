package p2p

func (s *Service) RequestBlocks(bm *BlockRequestMessage) error {
	peers := s.host.Peerstore().Peers()

	msg, err := bm.Encode()
	if err != nil {
		return err
	}

	//msg = append(Uint64ToLEB128(uint64(len(msg))), msg...)

	for _, pid := range peers {
		p, err := s.dht.FindPeer(s.ctx, pid)
		if err != nil {
			return err
		} else {
			err = s.Send(p, msg)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
