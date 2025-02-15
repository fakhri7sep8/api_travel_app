const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const db = require("../config/db");
require("dotenv").config()

const SECRET_KEY = process.env.SECRET_KEY || "secret";
const transporter = nodemailer.createTransport({
    host : "smtp.gmail.com",
    port: 587,
    secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

exports.register = async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
  if (password !== confirmPassword) return res.status(400).json({ message: "Password tidak cocok" });
  const hashedPassword = await bcrypt.hash(password, 10);
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  db.run(
    "INSERT INTO users (name, email, password, otp) VALUES (?, ?, ?, ?)",
    [name, email, hashedPassword, otp],
    function (err) {
      if (err) return res.status(500).json({ message: "Email sudah digunakan" });
      transporter.sendMail({ from: process.env.EMAIL_USER, to: email, subject: "Kode Verifikasi", text: `Kode OTP Anda: ${otp}` });
      res.json({ message: "Registrasi berhasil, cek email untuk OTP" });
    }
  );
};

exports.verify = (req, res) => {
  const { email, otp } = req.body;
  db.get("SELECT * FROM users WHERE email = ? AND otp = ?", [email, otp], (err, user) => {
    if (!user) return res.status(400).json({ message: "OTP salah atau email tidak ditemukan" });
    db.run("UPDATE users SET isVerif = 1, otp = NULL WHERE email = ?", [email]);
    res.json({ message: "Verifikasi berhasil" });
  });
};

exports.login = (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (!user) return res.status(400).json({ message: "Email atau password salah" });
    
    console.log("Password input:", password);
    console.log("Password DB:", user.password);

    // Bandingkan password yang diinput dengan password yang tersimpan
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Email atau password salah" });

    if (!user.isVerif) return res.status(400).json({ message: "Akun belum diverifikasi" });

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

    res.json({ status: "success", message: "Login berhasil", data: user, token });
  });
};

const crypto = require("crypto"); // Tambahkan ini di atas

exports.forgotPassword = (req, res) => {
  const { email } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (!user) return res.status(400).json({ message: "Email tidak ditemukan" });

    // Buat password baru secara acak (5 karakter)
    const newPassword = crypto.randomBytes(3).toString("hex");

    // Hash password sebelum disimpan
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    console.log("New Password:", newPassword);
    console.log("Hashed Password:", hashedPassword);

    // Simpan password baru ke database
    db.run("UPDATE users SET password = ? WHERE email = ?", [hashedPassword, email], (updateErr) => {
      if (updateErr) return res.status(500).json({ message: "Gagal menyimpan password baru" });

      // Kirim email dengan password baru
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Reset Password",
        text: `Password baru Anda adalah: ${newPassword}`,
      };

      transporter.sendMail(mailOptions, (mailErr) => {
        if (mailErr) return res.status(500).json({ message: "Gagal mengirim email" });

        res.json({ message: "Password baru telah dikirim ke email Anda" });
      });
    });
  });
};
