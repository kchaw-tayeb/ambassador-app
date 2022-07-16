import { Request, Response } from "express";
import { verify } from "jsonwebtoken";
import { getRepository } from "typeorm";
import { User } from "../entity/user.entity";

export const AuthMiddleware = async (
  req: Request,
  res: Response,
  next: Function
) => {
  try {
    const jwt = req.cookies["jwt"];
    const payload = verify(jwt, process.env.SECRET_KEY);
    if (!payload) {
      return res.status(401).send({
        message: "unauthenticated",
      });
    }

    const is_ambassador = req.path.indexOf("api/ambassador") >= 0;

    const user = await getRepository(User).findOneBy({
      id: payload["id"],
    });
    if (
      (is_ambassador && payload["scope"] !== "ambassador") ||
      (!is_ambassador && payload["scope"] !== "admin")
    ) {
      return res.status(401).send({
        message: "unauthorized",
      });
    }
    req["user"] = user;
    next();
  } catch (error) {
    return res.status(401).send({
      message: "unauthenticated",
    });
  }
};
