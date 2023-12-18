use windows::{
    core::*, Win32::Foundation::*, Win32::Storage::FileSystem::*, Win32::System::Threading::*,
    Win32::System::IO::*,
};
use std::{fs, ptr::null, io::Read, path::PathBuf};

pub struct DrivenManageImpl;

impl DrivenManageImpl {

    // Chekcout Driver Status
    pub fn GetStuFormDriver(strDrivenName:String) -> bool {
        
        return true;
    }

    // Open DriverHandle
    pub fn OpenDriverHandle(strDrivenName:String) -> HANDLE {
        unsafe {
            let dwAttribute: u32 = 1179785u32 | 1179926u32;
            let hResult: std::prelude::v1::Result<HANDLE, Error> = CreateFileA(
                PCSTR(strDrivenName.as_ptr()),
                dwAttribute,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                None,
            );

            if hResult.is_ok() {
                let hDriver: HANDLE = hResult.unwrap();
                return hDriver;
            }
            return HANDLE(0);
        }
    }

    // Send Data Pop Data
    pub fn  SendDataToDriver(iCode:u32, cData:String) -> bool {
        return true;
    }

    // Read Data Push Queue
    pub fn ReadDataFromDriver() {
        
    }
}