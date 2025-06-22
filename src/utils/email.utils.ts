import nodemailer from "nodemailer";

export const sendOtpEmail = async (to: string, otp: string) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });

    const mailOptions = {
      from: `"AuthPlug" <${process.env.SMTP_USER}>`,
      to,
      subject: "Verify Your Email - AuthPlug",
      html: `<p>Your OTP is: <b>${otp}</b>. It will expire in 10 minutes.</p>`,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("OTP Email sent: %s", info.messageId);
    return true;
  } catch (error) {
    console.error("Failed to send OTP email:", error);
    throw new Error("Could not send verification email. Try again later.");
  }
};
