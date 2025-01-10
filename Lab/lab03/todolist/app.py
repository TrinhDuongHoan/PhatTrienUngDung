from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, EqualTo, Email

app = Flask(__name__)

# Cấu hình cơ sở dữ liệu SQLite và Flask-Login
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'dev'  # Cần thiết cho Flask-Login
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirect đến trang login nếu chưa đăng nhập

# Mô hình người dùng (User)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Mô hình công việc (Todo)
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Cột liên kết với User
    user = db.relationship('User', backref=db.backref('todos', lazy=True))  # Quan hệ giữa Todo và User

# Hàm tải người dùng khi đăng nhập
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Form đăng ký người dùng mới
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

# Form đăng nhập
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

# Trang chính (Danh sách công việc)
@app.route('/')
@login_required  # Bảo vệ trang này, chỉ cho phép người dùng đã đăng nhập
def home():
    todo_list = Todo.query.filter_by(user_id=current_user.id).all()  # Lọc công việc theo người dùng
    return render_template('base.html', todo_list=todo_list)

# Thêm công việc mới
@app.route("/add", methods=["POST"])
@login_required  # Chỉ cho phép người dùng đã đăng nhập thêm công việc
def add():
    title = request.form.get("title")
    new_todo = Todo(title=title, complete=False, user_id=current_user.id)  # Liên kết công việc với người dùng
    db.session.add(new_todo)
    db.session.commit()
    return redirect(url_for("home"))

# Cập nhật công việc
@app.route("/update/<int:todo_id>")
@login_required
def update(todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()  # Kiểm tra công việc của người dùng
    if todo:
        todo.complete = not todo.complete
        db.session.commit()
    return redirect(url_for("home"))

# Xóa công việc
@app.route("/delete/<int:todo_id>")
@login_required
def delete(todo_id):
    todo = Todo.query.filter_by(id=todo_id, user_id=current_user.id).first()  # Kiểm tra công việc của người dùng
    if todo:
        db.session.delete(todo)
        db.session.commit()
    return redirect(url_for("home"))

# Trang đăng ký người dùng mới
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')  # Mã hóa mật khẩu

        # Kiểm tra xem tên người dùng đã tồn tại chưa
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another one.', 'danger')
            return redirect(url_for('register'))

        # Lưu người dùng vào cơ sở dữ liệu
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template("register.html", form=form)

# Trang đăng nhập
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Kiểm tra tên người dùng và mật khẩu
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("home"))
        else:
            flash('Login failed. Check your username and/or password.', 'danger')
    return render_template("login.html", form=form)

# Trang đăng xuất
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context(): 
        db.create_all()  # Tạo các bảng trong cơ sở dữ liệu nếu chưa tồn tại
    app.run(debug=True)
