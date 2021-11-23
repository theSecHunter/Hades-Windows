#include "grpc.h"

using namespace std;

bool Grpc::Grpc_Transfer(RawData rawData)
{
    /*
        Ë«Ïò steam
    */
    Status status;
    ClientContext context;

    // Read Server Msg
    //stream->Read(&nRetCommand);
    //status = stream->Finish();
    //if (false == status.ok())
    //{
    //    cout << "Read Buffer Error" << endl;
    //}
    // 
    // Write Server Msg
    bool nRet = false;
    if(Grpc_Getstream())
        nRet = m_stream->Write(rawData);
    if (false == nRet)
    {
        cout << "Write Buffer Error" << endl;
        return false;
    }

    return true;
}