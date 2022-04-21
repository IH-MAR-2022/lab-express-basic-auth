const isLoggedIn = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.render("index", { info: "Blocked by middleware" });
  }
};

module.exports = isLoggedIn;
