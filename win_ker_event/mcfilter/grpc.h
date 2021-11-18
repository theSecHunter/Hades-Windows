#pragma once
#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>
#include <grpc++/security/credentials.h>
#include <fstream>

#include "hades_win.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

using proto::Transfer;
using proto::RawData;
using proto::Command;

using namespace std;


const char servercert_path[] = "./ssl_key/server.crt";
const char clientcert_path[] = "./ssl_key/client.crt";
const char clientkey_path[] = "./ssl_key/client.key";

static std::string get_file_contents(const char* fpath)
{
	std::ifstream finstream(fpath);
	std::string contents;
	contents.assign((std::istreambuf_iterator<char>(finstream)),
		std::istreambuf_iterator<char>());
	finstream.close();
	return contents;
}

class Grpc
{
public:

	Grpc(std::shared_ptr<Channel> channel)
		: stub_(Transfer::NewStub(channel))
	{
	}
	
	~Grpc();

	bool Grpc_Transfer(RawData& rawData);

private:
	unique_ptr<Transfer::Stub> stub_;
};

