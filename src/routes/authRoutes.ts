import { Router, Request, Response, NextFunction } from "express";
import { z } from "zod";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { prisma } from "../config/database";

// Request body interfaces
interface RegisterRequestBody {
  phone: string;
  password: string;
  role: "REQUESTER" | "PROVIDER";
}

interface LoginRequestBody {
  phone: string;
  password: string;
}

interface ForgotPasswordRequestBody {
  phone: string;
}

interface ResetPasswordRequestBody {
  token: string;
  password: string;
}

// Validation schemas
const registerSchema = z.object({
  phone: z.string().regex(/^\+[1-9]\d{1,14}$/, "Invalid phone number"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  role: z.enum(["REQUESTER", "PROVIDER"]),
});

const loginSchema = z.object({
  phone: z.string().regex(/^\+[1-9]\d{1,14}$/, "Invalid phone number"),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

const forgotPasswordSchema = z.object({
  phone: z.string().regex(/^\+[1-9]\d{1,14}$/, "Invalid phone number"),
});

const resetPasswordSchema = z.object({
  token: z.string(),
  password: z.string().min(6, "Password must be at least 6 characters"),
});

const router = Router();


router.post(
  "/register",
  async (req: Request<{}, {}, RegisterRequestBody>, res: Response, next: NextFunction) => {
    try {
      const { phone, password, role } = registerSchema.parse(req.body);

      const existingUser = await prisma.user.findUnique({ where: { phone } });
      if (existingUser) {
        res.status(400).json({ message: "O numero de telefone já existe" });
        return;
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000);

      await prisma.user.create({
        data: {
          phone,
          password: hashedPassword,
          role,
          otp,
          otpExpiresAt,
        },
      });

      console.log(`OTP for ${phone}: ${otp}`);
      res.status(201).json({ message: "Usuario criado, codigo OTP enviado" });
    } catch (error) {
      console.error("Erro ao registar:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);


router.post(
  "/login",
  async (req: Request<{}, {}, LoginRequestBody>, res: Response, next: NextFunction) => {
    try {
      const { phone, password } = loginSchema.parse(req.body);

      const user = await prisma.user.findUnique({ where: { phone } });
      if (!user || !(await bcrypt.compare(password, user.password))) {
        res.status(401).json({ error: "Credenciais invalidas" });
        return;
      }

      const token = jwt.sign(
        { id: user.id, role: user.role },
        process.env.JWT_SECRET!,
        { expiresIn: "1h" }
      );

      res.status(200).json({ token });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

router.post(
  "/forgot-password",
  async (req: Request<{}, {}, ForgotPasswordRequestBody>, res: Response, next: NextFunction) => {
    try {
      const { phone } = forgotPasswordSchema.parse(req.body);

      const user = await prisma.user.findUnique({ where: { phone } });
      if (!user) {
        res.status(400).json({ error: "Usuario com este numero de telefone não existe" });
        return;
      }

      const resetToken = crypto.randomBytes(32).toString("hex");
      const resetTokenExpiresAt = new Date(Date.now() + 60 * 60 * 1000);

      await prisma.user.update({
        where: { id: user.id },
        data: { resetToken, resetTokenExpiresAt },
      });

      console.log(`link de restauro: http://localhost:3000/reset-password/${resetToken}`);
      res.status(200).json({ message: "link para resetar Password enviado" });
    } catch (error) {
      console.error("Forgot password error:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);


router.post(
  "/reset-password",
  async (req: Request<{}, {}, ResetPasswordRequestBody>, res: Response, next: NextFunction) => {
    try {
      const { token, password } = resetPasswordSchema.parse(req.body);

      const user = await prisma.user.findFirst({
        where: {
          resetToken: token,
          resetTokenExpiresAt: { gte: new Date() },
        },
      });

      if (!user) {
        res.status(400).json({ message: "Invalid or expired reset token" });
        return;
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      await prisma.user.update({
        where: { id: user.id },
        data: { password: hashedPassword, resetToken: null, resetTokenExpiresAt: null },
      });

      res.status(200).json({ message: "Password resetada com sucesso" });
    } catch (error) {
      res.status(500).json({ message: "Internal server error", error });
    }
  }
);

export default router;