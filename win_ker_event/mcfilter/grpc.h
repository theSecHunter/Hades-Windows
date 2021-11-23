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

const  char rootcrt_path[] = "./ssl_key/ca.crt";
const  char clientcrt_path[] = "./ssl_key/client.pem";
const  char clientkey_path[] = "./ssl_key/client_key.pem";

static std::string get_file_contents(const char* fpath)
{
	std::ifstream finstream((char*)fpath);
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
		m_stream = nullptr;
	}
	
	~Grpc()
	{
		Grpc_steamDon();
	}

	unique_ptr<::grpc::ClientReaderWriter<::proto::RawData, ::proto::Command>>  Grpc_streamInit()
	{
		
		 unique_ptr<::grpc::ClientReaderWriter<::proto::RawData, ::proto::Command>> stream(stub_->Transfer(&m_context));
		 return stream;
	}

	bool Grpc_Getstream()
	{
		if (!m_stream)
			m_stream = Grpc_streamInit();

		return true;
	}

	void Grpc_steamDon()
	{
		if (m_stream)
		{
			m_stream->WritesDone();
			m_stream->Finish();
			m_stream = nullptr;
		}
	}

	bool Grpc_Transfer(RawData rawData);

private:
	unique_ptr<Transfer::Stub> stub_;
	ClientContext m_context;
	unique_ptr<::grpc::ClientReaderWriter<::proto::RawData, ::proto::Command>> m_stream;
};

