export class AuthController {
  constructor({ authService }) {
    this.authService = authService;
  }

  signup = async (req, res) => {
    const result = await this.authService.signup(req.body);
    res.status(201).json(result);
  };

  login = async (req, res) => {
    const { accessToken, refreshToken } = await this.authService.login(
      req.body,
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/api/auth",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken });
  };
}
