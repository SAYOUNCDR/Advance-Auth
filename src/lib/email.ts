import nodemailer from "nodemailer";


export const sendEmail = async (to: string, subject: string, text: string) => {
    if (!process.env.SMTP_HOST || !process.env.SMTP_PORT || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
        throw new Error("SMTP configuration not found");
    }
    const host = process.env.SMTP_HOST;
    const port = Number(process.env.SMTP_PORT);
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    const from = process.env.EMAIL_FROM;

    const transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465, // should learn more about this
        auth: {
            user,
            pass
        }
    });

    const mailOptions = {
        from,
        to,
        subject,
        text
    };

    await transporter.sendMail(mailOptions);
}