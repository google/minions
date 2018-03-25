package overlord

import (
	pb "github.com/paradoxengine/minions/proto/overlord"
	"golang.org/x/net/context"
)

type Overlord struct {
}

func (s *Overlord) Scan(ctx context.Context, req *pb.ScanRequest) (*pb.ScanResponse, error) {
	return &pb.ScanResponse{"foo"}, nil
}
