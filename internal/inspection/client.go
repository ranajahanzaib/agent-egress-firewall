package inspection

import (
	"context"
	"fmt"

	"github.com/ranajahanzaib/agent-egress-firewall/internal/inspection/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn   *grpc.ClientConn
	client pb.InferenceServiceClient
}

func NewClient(address string) (*Client, error) {
	conn, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("creating gRPC client for %s: %w", address, err)
	}

	client := pb.NewInferenceServiceClient(conn)
	return &Client{
		conn:   conn,
		client: client,
	}, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *Client) Scan(ctx context.Context, req *pb.ScanRequest) (*pb.ScanResponse, error) {
	return c.client.Scan(ctx, req)
}

func (c *Client) CheckHealth(ctx context.Context) (*pb.HealthResponse, error) {
	return c.client.CheckHealth(ctx, &pb.HealthRequest{})
}

func (c *Client) GetModelStatus(ctx context.Context) (*pb.ModelStatusResponse, error) {
	return c.client.GetModelStatus(ctx, &pb.ModelStatusRequest{})
}
