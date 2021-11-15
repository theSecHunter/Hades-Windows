#pragma once
#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include "hades_win.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using proto::Transfer;

using namespace std;

class Grpc
{
public:
	Grpc(shared_ptr<Channel> channel)
		: stub_(Transfer::NewStub(channel))
	{

	}
	~Grpc();

	bool Grpc_Init();

private:
	std::unique_ptr<Transfer::Stub> stub_;
};

