const nodemailer = require("nodemailer");

const sendEmail = async (options) => {
  const transpoter = nodemailer.createTransport({
    service: process.env.SMTP_SERVICE,
    auth: {
      user: process.env.SMTP_MAIL,
      pass: process.env.SMTP_PASSWORD,
    },
  });
  const mailOptions = {
    from: `Hi-here <${process.env.SMTP_MAIL}$>`,
    to: options.email,
    subject: options.subject,
    text: options.text,
    html: `This is your otp ${options.text}`,
  };
  await transpoter.sendMail(mailOptions);
};
module.exports = sendEmail;
