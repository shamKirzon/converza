import { useResolvedPath } from 'react-router-dom';
import { generateJwtToken } from '../lib/utils';
import User from '../models/user.model';
import bcrypt from 'bcryptjs';
import { error } from 'console';

export const signup = async (req: any, res: any) => {
  const { email, fullName, password } = req.body.data;
  console.log(req.body.data);
  console.log(email, fullName, password, '');

  try {
    if (!email || !fullName || !password)
      return res.status(400).json({ message: 'All fields are required' });
    if (password.length < 6)
      return res
        .status(400)
        .json({ message: 'Password must be at least 6 characters' });

    const user = await User.findOne({ email });

    if (user)
      return res.status(400).json({ message: 'Email already exists. ' });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      fullName,
      password: hashedPassword,
    });

    if (newUser) {
      generateJwtToken(newUser._id, res);
      await newUser.save();

      res.status(201).json({
        _id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        profilePicture: newUser.profilePicture,
        password: newUser.password,
      });
    } else {
      return res.status(400).json({ message: 'Invalid user data ' });
    }
  } catch (error) {
    console.log('Error in authControlller ', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
};

export const login = async (req: any, res: any) => {
  const { email, password } = req.body.data;

  try {
    if (!email || !password)
      return res.status(400).json({ message: 'All fields are required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found. ' });

    const isPassMatch = await bcrypt.compare(password, user.password);

    if (!isPassMatch)
      return res
        .status(401)
        .json({ message: 'Incorrect password', err: password });

    generateJwtToken(user._id, res);

    res.status(200).json({
      _id: user._id,
      fullname: user.fullName,
      email: user.email,
      profilePicture: user.profilePicture,
    });
  } catch (error) {
    console.log('authController/login error: ', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
};

export const logout = async (req: any, res: any) => {
  try {
    res.cookie('jwt', '', { maxAge: 0 });
    res.status(200).json({ message: 'Logout successfully' });
  } catch (error) {
    console.error('authController/logout error: ', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
};

export const checkAuth = (req: any, res: any) => {
  try {
    res.status(200).json(req.user);
  } catch (error) {
    console.log('error in checkAuth controller ', error);
    res.status(400).json({ message: 'Internal Server Error' });
  }
};

/**
 * to do list:
 * cookie()
 * if yes,
 *
 * add validation in authUser. (if merong cookie)
 *
 * check if may cookie, if meron, basta
 */
