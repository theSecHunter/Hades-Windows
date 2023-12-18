use fast_log::{consts::LogSize, plugin::{file_split::RollingType, packer::LogPacker}};
use netCom::RuleImpl;


#[test]
pub fn UnitGetDnsRule() {
    let mut sYamData: String = String::from("");
    let mut sCurrentPath = std::env::current_dir().unwrap().to_str().unwrap().to_string();
    if sCurrentPath.is_empty() {
        log::error!("Get Rule DirPath Failuer.");
        return;
    }
    let sNetRulePath: String = sCurrentPath + "\\config\\networkRuleConfig.yaml";
    let bRet: bool = RuleImpl::GetDnsRule(sNetRulePath, &mut sYamData);
    if false == bRet {
        log::error!("Get Rule DirPath Failuer.");
        return;
    }
    println!("Analyze Rule Success. {}",sYamData);
}