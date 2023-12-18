use netCom::DrivenManageImpl;

#[test]
// 驱动启动状态
pub fn UnitGetDrivenStu() {
    let strDrivenName :String= String::from("\\??\\Hades");
    DrivenManageImpl::OpenDriverHandle(strDrivenName);
}