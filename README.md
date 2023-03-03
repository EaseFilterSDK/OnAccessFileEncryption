# [Transparent On Access File Encryption](https://www.easefilter.com/kb/transparent-on-access-file-encryption-SDK.htm)
EaseFilter Transparent On Access File Encryption SDK was implemented with the EaseFilter Encryption Filter Driver (EEFD). The EEFD provides a comprehensive security solution to develop the transparent on access file level encryption products. Encrypt the newly created files transparently. Authorize or block the on access encryption/decryption under the control of client-defined policy.
 
## Easefilter Encryption Filter Driver (EEFD)

EEFD is a file system file level encryption filter driver. It intercepts the I/O requests targeted at a file system. By intercepting the request before it reaches its intended target file system, the filter driver can encrypt or decrypt the data buffer provided by the original target of the request. Even though there is a lot of encryption libraries in the market, but it is still very complex to develop a reliable transparent on access file encryption product. The EEFD is a mature commercial product. It provides a complete modular framework for the developers even without the driver development experience to build the on access file encryption software within a day. 

![Trnasparent File Encryption](https://www.easefilter.com/Images/TransparentFileEncryption.png)

## FIPS Compliant Encryption

The EEFD utilizes the Microsoft CNG encryption libraries with the AES algorithm. The AES Encryption algorithm (also known as the Rijndael algorithm) is a specification for the encryption of electronic data established by the U.S. National Institute of Standards and Technology (NIST) in 2001.  AES is a US FIPS 140-2 compliant symmetric block cipher algorithm.  It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits.

## Per Process Access Restriction

The EEFD supports the per process access restriction for the on access file encryption. You an setup the whitelist or blacklist of the processes to the encrypted files. The whitelist process can read the encrypted file to get the clear text. The blacklist process only can get the encrypted raw data. The EEFD utilizes the Isolation Mini Filter Driver technology to implement two views of the encrypted file to the process. The unauthorized process will see the encrypted data view with the raw ciphertext. The authorized processes will see the decrypted data view with the plaintext.

![Isolation Filter Driver](https://www.easefilter.com/images/IsolationFilter.png)

## The Encrypted File Header with DRM Embedded

The EEFD supports the encryption header with the custom digital rights management (DRM) data embedded to the encrypted file. With the custom DRM data, you can define your custom encryption access policies, it allows you to fully control the encrypted file access dynamically. You can grant, revoke or expire the encrypted file access at any time, even after the encrypted file has been sent out of your organization. You can develop the security application to implement the secure file sharing solution with the EEFD.

![Secure File Sharing](https://www.easefilter.com/images/SecureSharing.png)

## High Performance For Encryption

The CNG encryption library supports AES-NI (or the Intel Advanced Encryption Standard New Instructions; AES-NI). With the hardware-assisted support, it utilizes the hardware enhanced cryptography, it can achieve greater speeds and / or improved security than otherwise. The EEFD utilizes the AES block cipher algorithm, it allows you to encrypt or decrypt the encrypted file at any block (16 bytes). You can read the random block of the encrypted file without the whole file decryption needed. The EEFD integrates the block cipher operation in the same read or write IO, without the extra IO required. The block cipher improves the encryption or decryption performance dramatically. 

## The Use Cases with EEFD

1. **Data encryption at rest.** Encryption at rest prevents the attacker from accessing the unencrypted data by ensuring the data is encrypted when on disk. 
2. **Data protection.** Document encryption, file encryption is very important step for data protection, only the authorized users or processes can read the encrypted data, or will get the raw encrypted data.
3. **Data loss prevention.** To prevent the data breach, your data is encrypted all the time, even your data was lost and found in an unauthorized place, they are protected against the unauthorized access.
4. **Secure file sharing with DRM.** Encrypted your files with digital rights management data embedded into the encrypted header, protect, track and control your encrypted files anywhere anytime, you can grant or revoke the access control to any user at any time even the files were shared.
   
## A Transparent On Access File Encryption Example

Here is a c# on access file encryption example to demonstrate how to use the SDK. First you need to setup an encryption folder in computer A. You can configure the authorized processes and users who can read the encrypted file. Then you can setup the decryption folder in computer B if you want to distribute the encrypted file to the computer B. In order to access the encrypted file in computer B, you need to setup the authorized processes, only the authorized processes can access the encrypted files.

![File Encryption Demo](https://www.easefilter.com/images/autoencryptdemo.png)

<pre><code class='language-mylanguage'>
namespace AutoFileEncryption
{
    class Program
    {
        static FilterControl filterControl = new FilterControl();

        static void Main(string[] args)
        {
            string lastError = string.Empty;
            string licenseKey = "Email us to request a trial key: info@easefilter.com";

            FilterAPI.FilterType filterType = FilterAPI.FilterType.CONTROL_FILTER
			| FilterAPI.FilterType.ENCRYPTION_FILTER | FilterAPI.FilterType.PROCESS_FILTER;
            int serviceThreads = 5;
            int connectionTimeOut = 10; //seconds

            try
            {
                //copy the right Dlls to the current folder.
                Utils.CopyOSPlatformDependentFiles(ref lastError);

                if (!filterControl.StartFilter(filterType, serviceThreads, connectionTimeOut, licenseKey, ref lastError))
                {
                    Console.WriteLine("Start Filter Service failed with error:" + lastError);
                    return;
                }
                        
                //setup a file filter rule for folder encryptFolder
                string encryptFolder = "c:\\encryptFolder\\*";
                FileFilter fileFilter = new FileFilter(encryptFolder);

                //enable the encryption for the filter rule.
                fileFilter.EnableEncryption = true;

                //get the 256bits encryption key with the passphrase
                string passPhrase = "mypassword";
                fileFilter.EncryptionKey = Utils.GetKeyByPassPhrase(passPhrase, 32);

                //disable the decyrption right, read the raw encrypted data for all except the authorized processes or users.
                fileFilter.EnableReadEncryptedData = false;

                //setup the authorized processes to decrypt the encrypted files.
                string authorizedProcessesForEncryptFolder = "notepad.exe;wordpad.exe";

                string[] processNames = authorizedProcessesForEncryptFolder.Split(new char[] { ';' });
                if (processNames.Length > 0)
                {
                    foreach (string processName in processNames)
                    {
                        if (processName.Trim().Length > 0)
                        {
                            //authorized the process with the read encrypted data right.
                            fileFilter.ProcessNameAccessRightList.Add(processName, FilterAPI.ALLOW_MAX_RIGHT_ACCESS);
                        }
                    }
                }

                //setup the authorized users to decrypt the encrypted files.
                string authorizedUsersForEncryptFolder = "domainName\\user1";

                if (!string.IsNullOrEmpty(authorizedUsersForEncryptFolder) && !authorizedUsersForEncryptFolder.Equals("*"))
                {
                    string[] userNames = authorizedUsersForEncryptFolder.Split(new char[] { ';' });
                    if (userNames.Length > 0)
                    {
                        foreach (string userName in userNames)
                        {
                            if (userName.Trim().Length > 0)
                            {
                                //authorized the user with the read encrypted data right.
                                fileFilter.userAccessRightList.Add(userName, FilterAPI.ALLOW_MAX_RIGHT_ACCESS);
                            }
                        }
                    }

                    if (fileFilter.userAccessRightList.Count > 0)
                    {
                        //set black list for all other users except the white list users.
                        uint accessFlag = FilterAPI.ALLOW_MAX_RIGHT_ACCESS & ~(uint)FilterAPI.AccessFlag.ALLOW_READ_ENCRYPTED_FILES;
                        //disable the decryption right, read the raw encrypted data for all except the authorized users.
                        fileFilter.userAccessRightList.Add("*", accessFlag);
                    }
                }

                //add the encryption file filter rule to the filter control
                filterControl.AddFilter(fileFilter);

                //setup a file filter rule for folder decryptFolder
                string decryptFolder = "c:\\decryptFolder\\*";                
                FileFilter decryptFileFilter = new FileFilter(decryptFolder);

                //enable the encryption for the filter rule.
                decryptFileFilter.EnableEncryption = true;

                //get the 256bits encryption key with the passphrase
                decryptFileFilter.EncryptionKey = Utils.GetKeyByPassPhrase(passPhrase, 32);

                //don't encrypt the new created file in the folder.
                decryptFileFilter.EnableEncryptNewFile = false;

                //disable the decyrption right, read the raw encrypted data for all except the authorized processes or users.
                decryptFileFilter.EnableReadEncryptedData = false;

                //setup authorized processes to decrypt the encrypted files.
                string authorizedProcessesForDecryptFolder = "notepad.exe;wordpad.exe";

                processNames = authorizedProcessesForDecryptFolder.Split(new char[] { ';' });
                if (processNames.Length > 0)
                {
                    foreach (string processName in processNames)
                    {
                        if (processName.Trim().Length > 0)
                        {
                            //authorized the process with the read encrypted data right.
                            decryptFileFilter.ProcessNameAccessRightList.Add(processName, FilterAPI.ALLOW_MAX_RIGHT_ACCESS);
                        }
                    }
                }

                filterControl.AddFilter(decryptFileFilter);

                if (!filterControl.SendConfigSettingsToFilter(ref lastError))
                {
                    Console.WriteLine("SendConfigSettingsToFilter failed." + lastError);
                    return;
                }

                Console.WriteLine("Start filter service succeeded.");

                // Wait for the user to quit the program.
                Console.WriteLine("Press 'q' to quit the sample.");
                while (Console.Read() != 'q') ;

                filterControl.StopFilter();

            }
            catch (Exception ex)
            {
                Console.WriteLine("Start filter service failed with error:" + ex.Message);
            }

        }

    }
}

</pre>

[Read more about auto file encryption example](https://www.easefilter.com/Forums_Files/AutoFileEncryption.htm)
