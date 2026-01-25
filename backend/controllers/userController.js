import TryCatch from "../middlewares/errorHandling.js";
import sanitize from "mongo-sanitize";

export const registerUser = TryCatch(async (req, res) => {
  const { name, email, password } = sanitize(req.body);

  // Registration logic here
  res.json({
    name,
    email,
    password,
  });
});
