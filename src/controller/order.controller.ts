import { Request, Response } from "express";
import { getConnection, getRepository } from "typeorm";
import { Order } from "../entity/order.entity";
import { Link } from "../entity/link.entity";
import { Product } from "../entity/product.entity";
import { OrderItem } from "../entity/order-item.entity";
// import Stripe from "stripe";
// import {client} from "../index";
import { User } from "../entity/user.entity";
// import {createTransport} from "nodemailer";

export const Orders = async (req: Request, res: Response) => {
  const orders = await getRepository(Order).find({
    where: { complete: true },
    relations: ["order_items"],
  });

  res.send(
    orders.map((order: Order) => ({
      id: order.id,
      name: order.name,
      email: order.email,
      total: order.total,
      created_at: order.created_at,
      order_items: order.order_items,
    }))
  );
};
