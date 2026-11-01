import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { createHash, randomBytes } from "node:crypto";
import { conflict } from "../utils/http-error.js";
import { unauthorized } from "../utils/http-error.js";

export class AuthService {
  constructor({ authRepository }) {
    this.authRepository = authRepository;
  }

  async signup({ email, nickname, password }) {
    const emailUser = await this.authRepository.findByEmail(email);
    if (emailUser) throw conflict("이미 사용 중인 이메일입니다.");

    const nicknameUser = await this.authRepository.findByNickname(nickname);
    if (nicknameUser) throw conflict("이미 사용 중인 닉네임입니다.");

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.authRepository.createUser({
      email,
      nickname,
      password: hashedPassword,
    });

    return {
      id: user.id,
      email: user.email,
      nickname: user.nickname,
    };
  }

  async login({ email, password }) {
    const user = await this.authRepository.findByEmail(email);
    if (!user || !user.password) throw unauthorized();

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) throw unauthorized();

    const accessToken = jwt.sign(
      { userId: user.id },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: "15m" },
    );

    const refreshToken = randomBytes(64).toString("hex");
    const tokenHash = createHash("sha256").update(refreshToken).digest("hex");

    const expiresAt = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000,
    ).toISOString();

    await this.authRepository.createRefreshToken({
      userId: user.id,
      tokenHash,
      expiresAt,
    });

    return { accessToken, refreshToken };
  }
}
