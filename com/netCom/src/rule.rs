extern crate yaml_rust;

use std::{fs, ptr::null, io::Read, path::PathBuf};
use yaml_rust::{YamlLoader, YamlEmitter};

pub struct RuleImpl;

impl RuleImpl {
    // Read json, yaml Data
    fn ReadFileRule(sRulePath: String, sYamData: &mut String) -> bool {
        if sRulePath.is_empty() || null() == sYamData {
            return false;
        }
        if !PathBuf::from(sRulePath.to_string()).exists() {
            log::error!("Checkout Yaml File exists failuer. {}", sRulePath);
            return false;
        }
        *sYamData = fs::read_to_string(sRulePath.to_string()).unwrap();
        return true;
    }

    // Analyze dns rule
    pub fn GetDnsRule(sRulePath: String,  sYamData: &mut String) -> bool {
        if sRulePath.is_empty() {
            return false;
        }
        
        RuleImpl::ReadFileRule(sRulePath, sYamData);
        if sYamData.is_empty() {
            return false;
        }

        let docs: Vec<yaml_rust::Yaml> = YamlLoader::load_from_str(sYamData).unwrap();

        // Multi document support, doc is a yaml::Yaml
        let doc: &yaml_rust::Yaml = &docs[0];
    
        // Debug support
        println!("{:?}", doc);
    
        // Index access for map & array
        // assert_eq!(doc["foo"][0].as_str().unwrap(), "list1");
        // assert_eq!(doc["bar"][1].as_f64().unwrap(), 2.0);
    
        // // Chained key/array access is checked and won't panic,
        // // return BadValue if they are not exist.
        // assert!(doc["INVALID_KEY"][100].is_badvalue());
    
        // // Dump the YAML object
        // let mut out_str = String::new();
        // {
        //     let mut emitter = YamlEmitter::new(&mut out_str);
        //     emitter.dump(doc).unwrap(); // dump the YAML object to a String
        // }
        // println!("{}", out_str);
        return true;
    }

    // Analyze Redirect rule
    pub fn GetRedirectRule(sRulePath:String) {

    }

    // Analyze transport layer rule
    pub fn GetTransportNetRule(sRulePath:String) {

    }

}

// Unit test
#[cfg(test)]
mod test{
    
}

