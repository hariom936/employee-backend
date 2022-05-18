const bcrypt = require("bcryptjs");
const Joi = require("@hapi/joi");

const employeeModel = require("../model/employee");

exports.employeeSignup = async (req, res) => {
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

exports.employeeSignin = async (req, res) => {
  const employee = await employeeModel.findOne({ email: req.body.email });

  if (!employee) return res.send("Please signup");

  const validatePassword = await bcrypt.compare(
    req.body.password,
    employee.password
  );

  if (!validatePassword) return res.send("Incorrect password");

  try {
    const signinSchema = Joi.object({
      email: Joi.string().min(6).required().email(),
      password: Joi.string().min(8).required(),
    });

    const { error } = await signinSchema.validateAsync(req.body);

    if (error) return res.send(error.details[0].message);
    else {
      res.send(employee);
    }
  } catch (error) {
    res.send(error);
  }
};
