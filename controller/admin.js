const bcrypt = require("bcryptjs");
const Joi = require("@hapi/joi");
const jwt = require("jsonwebtoken");

const adminModel = require("../model/admin");
const employeeModel = require("../model/employee");

exports.adminSignup = async (req, res) => {
  const emailExist = await adminModel.findOne({ email: req.body.email });
  if (emailExist) {
    res.send("Email Already Exist");
    return;
  }
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  try {
    const signupSchema = Joi.object({
      name: Joi.string().min(3).required(),
      userName: Joi.string().min(3).required(),
      email: Joi.string().min(6).required().email(),
      password: Joi.string().min(8).required(),
    });

    const { error } = await signupSchema.validateAsync(req.body);

    if (error) {
      res.send(error.details[0].message);
    } else {
      const admin = new adminModel({
        name: req.body.name,
        userName: req.body.userName,
        email: req.body.email,
        password: hashedPassword,
      });

      const saveAdmin = await admin.save();
      res.send("Admin Signup Completed");
    }
  } catch (error) {
    res.send(error);
  }
};

exports.adminSignin = async (req, res) => {
  const admin = await adminModel.findOne({ email: req.body.email });

  if (!admin) return res.send("Please SignUp");

  const validatePassword = await bcrypt.compare(
    req.body.password,
    admin.password
  );

  if (!validatePassword) return res.send("Incorrect Password");

  try {
    const signinSchema = Joi.object({
      email: Joi.string().min(6).required().email(),
      password: Joi.string().min(8).required(),
    });

    const { error } = await signinSchema.validateAsync(req.body);

    if (error) return res.send(error.details[0].message);
    else {
      const token = jwt.sign({ _id: admin._id }, process.env.TOKEN_SECRET);
      res.send({ token: token, admin: admin });
    }
  } catch (error) {
    res.send(error);
  }
};

exports.getAllEmployee = async (req, res) => {
  const employees = await employeeModel.find();
  try {
    res.send(employees);
  } catch (error) {
    res.send(error);
  }
};

exports.deleteEmployee = (req, res) => {
  employeeModel.deleteOne({ _id: req.params.id }, (error) => {
    if (error) {
      res.send(error);
    } else {
      res.send("Deleted");
    }
  });
};

exports.editEmployee = (req, res) => {
  employeeModel.findOne({ _id: req.params.id }, (error, employee) => {
    if (error) {
      res.send(error);
    } else {
      employee.name = req.body.name
        ? req.body.name
        : employee.userName;
      employee.userName = req.body.userName
        ? req.body.userName
        : employee.userName;
      employee.save((error) => {
        if (error) {
          res.send(error);
        } else {
          res.send("Edited");
        }
      });
    }
  });
};

exports.addEmployee = async (req, res) => {
  const emailExist = await employeeModel.findOne({ email: req.body.email });
  if (emailExist) {
    res.send("Email Already Exist");
    return;
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  try {
    const signupSchema = Joi.object({
      name: Joi.string().min(3).required(),
      userName: Joi.string().min(3).required(),
      email: Joi.string().min(6).required().email(),
      password: Joi.string().min(8).required(),
    });

    const { error } = await signupSchema.validateAsync(req.body);

    if (error) {
      res.send(error.details[0].message);
    } else {
      const employee = new employeeModel({
        name: req.body.name,
        userName: req.body.userName,
        email: req.body.email,
        password: hashedPassword,
      });

      const saveEmployee = await employee.save();
      res.send("Employee Signup Completed");
    }
  } catch (error) {
    res.send(error);
  }
};
