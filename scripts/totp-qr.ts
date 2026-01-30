import QRCode from "qrcode"; 


const otpAuthUrl = process.argv[2];
 
if(!otpAuthUrl) {
    throw new Error("Please provide an OTP Auth URL");
}


async function main() {
    await QRCode.toFile('totp.png', otpAuthUrl);
    console.log("QR code generated successfully");
}


main().catch(error => {
    console.error(error);
    process.exit(1);
});
