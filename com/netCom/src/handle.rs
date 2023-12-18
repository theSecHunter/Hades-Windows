// network packet filter handle
pub struct HandleMSG;

impl HandleMSG {


    // Handle Message
    fn HandleMSGNotify() -> bool {
        return true;
    }

    // When Waiting For Queue Data, The Data Pop is Dispatch.
    pub fn WaitiQueueDataDispatch() -> bool {
        return true;
    }

}