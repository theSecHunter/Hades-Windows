#include "grpc.h"

using namespace std;

Grpc::~Grpc()
{

}

bool Grpc::Grpc_Init()
{
	string ip_port = "localhost:50051";
	auto nret =  grpc::CreateChannel(ip_port, grpc::InsecureChannelCredentials());

	return true;
}