#include "grpc.h"

using namespace std;

Grpc::~Grpc()
{

}

bool Grpc::Grpc_Transfer(RawData* rawData)
{
    if (!rawData)
        return false;
    stub_->Transfer(rawData);
}