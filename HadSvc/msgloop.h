#pragma once
class WinMsgLoop
{
public:
	WinMsgLoop();
	~WinMsgLoop();

	// Wait DlgView Recv C2
	void MsgThreadC2HandlerLoop();
private:

};