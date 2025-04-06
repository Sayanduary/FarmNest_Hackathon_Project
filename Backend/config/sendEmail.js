// utils/sendEmail.js (or wherever it is)
import nodemailer from 'nodemailer';

const sendEmail = async ({ sendTo, subject, html }) => {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASS,
      },
      tls: { rejectUnauthorized: false },
    });

    const mailOptions = {
      from: `"FarmNest" <${process.env.EMAIL}>`,
      to: sendTo, // ✅ Fix here
      subject,
      html,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("✅ Email sent:", info.response);
  } catch (error) {
    console.error("❌ Failed to send email:", error);
  }
};

export default sendEmail;
