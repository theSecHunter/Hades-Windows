#include "grpc.h"

using namespace std;

Grpc::~Grpc()
{
}

bool Grpc::Grpc_Transfer(RawData& rawData)
{
    /*
        Ë«Ïò steam
    */
    Status status;
    Command nRetCommand;
    ClientContext context;

    std::unique_ptr< ::grpc::ClientReaderWriter< ::proto::RawData, ::proto::Command > >
        stream(stub_->Transfer(&context));

    // Read Server Msg
    //stream->Read(&nRetCommand);
    //status = stream->Finish();
    //if (false == status.ok())
    //{
    //    cout << "Read Buffer Error" << endl;
    //}

    // Write Server Msg
    auto nRet = stream->Write(rawData);   
    stream->WritesDone();
    status = stream->Finish();
    if (false == status.ok())
    {
        cout << "Write Buffer Error" << endl;
        return false;
    }

    return true;
}