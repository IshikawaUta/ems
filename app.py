from flask import Flask, render_template, request, redirect, url_for, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
from dotenv import load_dotenv
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config.from_object('config.Config')

# Inisialisasi Flask-Login dan Flask-Bcrypt
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

# MongoDB Connection
client = MongoClient(app.config['MONGO_URI'])
db = client.employee_management_db

# Collections
employees_collection = db.employees
attendance_collection = db.attendance
recruitment_collection = db.recruitment
leave_collection = db.leave
payroll_collection = db.payroll
projects_collection = db.projects
scheduling_collection = db.scheduling
app_settings_collection = db.app_settings
users_collection = db.users
integrations_collection = db.integrations

# --- User Model untuk Flask-Login ---
class User(UserMixin):
    def __init__(self, user_data):
        self.user_data = user_data
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.role = user_data.get('role', 'employee')

    def get_id(self):
        return self.id

    def has_role(self, *roles):
        return self.role in roles

# --- User Loader untuk Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

# --- Decorator untuk Role-Based Access Control (RBAC) ---
def role_required(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Anda harus login untuk mengakses halaman ini.', 'warning')
                return redirect(url_for('login'))
            if not current_user.has_role(*roles):
                flash('Anda tidak memiliki izin untuk mengakses halaman ini.', 'danger')
                return redirect(url_for('index'))
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

# --- Routes Autentikasi ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = users_collection.find_one({'username': username})

        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            user = User(user_data)
            login_user(user)
            flash('Login berhasil!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Username atau kata sandi salah.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Untuk keamanan, biasanya pendaftaran admin hanya dilakukan sekali atau oleh admin lain.
    # Untuk contoh ini, kita biarkan bisa diakses, tapi di produksi harus dilindungi!
    if current_user.is_authenticated and not current_user.has_role('admin'):
        flash('Anda tidak memiliki izin untuk mendaftar pengguna baru.', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'employee')

        if users_collection.find_one({'username': username}):
            flash('Username sudah ada, pilih username lain.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users_collection.insert_one({'username': username, 'password': hashed_password, 'role': role})
            flash('Pengguna berhasil didaftarkan!', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

# --- Rute Profil Pengguna ---
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    # Ambil data pengguna yang sedang login
    user_data = users_collection.find_one({'_id': ObjectId(current_user.id)})
    
    if not user_data: # Fallback jika data pengguna tidak ditemukan (jarang terjadi jika sudah login)
        flash('Data profil Anda tidak ditemukan.', 'danger')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        new_username = request.form['username']
        new_password = request.form.get('password')

        # Cek jika username diubah dan sudah ada yang lain
        if new_username != user_data['username']:
            existing_user = users_collection.find_one({'username': new_username})
            if existing_user and str(existing_user['_id']) != str(user_data['_id']): # Pastikan bukan diri sendiri
                flash('Username sudah ada, pilih username lain.', 'danger')
                return render_template('edit_profile.html', user=user_data)

        update_data = {'username': new_username}

        if new_password: # Hanya update password jika diisi
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            update_data['password'] = hashed_password

        # Simpan ID pengguna sebelum logout
        user_id_before_logout = current_user.id 
        
        # Update data pengguna di database
        users_collection.update_one(
            {'_id': ObjectId(user_id_before_logout)}, # Gunakan ID yang disimpan
            {'$set': update_data}
        )
        
        # Karena data pengguna di sesi mungkin sudah kadaluarsa (terutama username),
        # kita perlu memuat ulang objek user Flask-Login.
        # Strategi: Logout sementara, muat ulang data, lalu login kembali.
        logout_user() # Logout user sementara, current_user sekarang AnonymousUserMixin
        
        # Ambil data yang baru menggunakan ID yang disimpan
        re_user_data = users_collection.find_one({'_id': ObjectId(user_id_before_logout)}) 
        
        if re_user_data:
            re_user = User(re_user_data)
            login_user(re_user) # Login kembali dengan data baru
            flash('Profil berhasil diperbarui!', 'success')
        else:
            flash('Gagal memuat ulang profil. Silakan login kembali.', 'warning')
            return redirect(url_for('login')) # Arahkan ke login jika gagal memuat ulang

        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user_data)

# --- Routes Aplikasi (dilindungi) ---
@app.route('/')
@login_required # Halaman utama hanya bisa diakses setelah login
def index():
    return render_template('index.html')

# --- Karyawan ---
@app.route('/employees')
@login_required
@role_required('admin', 'manager', 'employee')
def employees():
    all_employees = list(employees_collection.find())
    return render_template('employees/list.html', employees=all_employees)

@app.route('/employees/add', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager')
def add_employee():
    if request.method == 'POST':
        name = request.form['name']
        position = request.form['position']
        contact = request.form['contact']
        employees_collection.insert_one({'name': name, 'position': position, 'contact': contact})
        flash('Karyawan berhasil ditambahkan!', 'success')
        return redirect(url_for('employees'))
    return render_template('employees/add.html')

@app.route('/employees/edit/<id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager')
def edit_employee(id):
    employee = employees_collection.find_one({'_id': ObjectId(id)})
    if not employee:
        flash('Karyawan tidak ditemukan!', 'danger')
        return redirect(url_for('employees'))
    if request.method == 'POST':
        name = request.form['name']
        position = request.form['position']
        contact = request.form['contact']
        employees_collection.update_one({'_id': ObjectId(id)}, {'$set': {'name': name, 'position': position, 'contact': contact}})
        flash('Data karyawan berhasil diperbarui!', 'success')
        return redirect(url_for('employees'))
    return render_template('employees/edit.html', employee=employee)

@app.route('/employees/delete/<id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_employee(id):
    employees_collection.delete_one({'_id': ObjectId(id)})
    flash('Karyawan berhasil dihapus!', 'success')
    return redirect(url_for('employees'))

# --- Absensi ---
@app.route('/attendance')
@login_required
@role_required('admin', 'manager', 'employee')
def attendance():
    all_attendance = list(attendance_collection.find().sort("date", -1))
    return render_template('attendance/list.html', attendance=all_attendance)

@app.route('/attendance/record', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager', 'employee')
def record_attendance():
    all_employees = list(employees_collection.find())
    if request.method == 'POST':
        employee_id = request.form['employee_id']
        status = request.form['status']
        date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        employee = employees_collection.find_one({'_id': ObjectId(employee_id)})
        if employee:
            attendance_collection.insert_one({
                'employee_id': ObjectId(employee_id),
                'employee_name': employee['name'],
                'date': date,
                'status': status
            })
            flash('Absensi berhasil dicatat!', 'success')
        else:
            flash('Karyawan tidak ditemukan!', 'danger')
        return redirect(url_for('attendance'))
    return render_template('attendance/record.html', employees=all_employees)

# --- Rekrutmen ---
@app.route('/recruitment')
@login_required
@role_required('admin', 'manager')
def recruitment():
    all_applicants = list(recruitment_collection.find())
    return render_template('recruitment/list.html', applicants=all_applicants)

@app.route('/recruitment/add', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager')
def add_applicant():
    if request.method == 'POST':
        name = request.form['name']
        position_applied = request.form['position_applied']
        status = request.form['status']
        recruitment_collection.insert_one({'name': name, 'position_applied': position_applied, 'status': status, 'date_applied': datetime.now().strftime("%Y-%m-%d")})
        flash('Pelamar berhasil ditambahkan!', 'success')
        return redirect(url_for('recruitment'))
    return render_template('recruitment/add.html')

@app.route('/recruitment/edit/<id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager')
def edit_applicant(id):
    applicant = recruitment_collection.find_one({'_id': ObjectId(id)})
    if not applicant:
        flash('Pelamar tidak ditemukan!', 'danger')
        return redirect(url_for('recruitment'))

    if request.method == 'POST':
        name = request.form['name']
        position_applied = request.form['position_applied']
        status = request.form['status']
        recruitment_collection.update_one(
            {'_id': ObjectId(id)},
            {'$set': {'name': name, 'position_applied': position_applied, 'status': status}}
        )
        flash('Data pelamar berhasil diperbarui!', 'success')
        return redirect(url_for('recruitment'))
    return render_template('recruitment/edit.html', applicant=applicant)

@app.route('/recruitment/delete/<id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_applicant(id):
    recruitment_collection.delete_one({'_id': ObjectId(id)})
    flash('Pelamar berhasil dihapus!', 'success')
    return redirect(url_for('recruitment'))

# --- Cuti ---
@app.route('/leave')
@login_required
@role_required('admin', 'manager', 'employee')
def leave():
    all_leave_requests = list(leave_collection.find())
    return render_template('leave/list.html', leave_requests=all_leave_requests)

@app.route('/leave/request', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager', 'employee')
def request_leave():
    all_employees = list(employees_collection.find())
    if request.method == 'POST':
        employee_id = request.form['employee_id']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        reason = request.form['reason']
        status = 'Pending'
        employee = employees_collection.find_one({'_id': ObjectId(employee_id)})
        if employee:
            leave_collection.insert_one({
                'employee_id': ObjectId(employee_id),
                'employee_name': employee['name'],
                'start_date': start_date,
                'end_date': end_date,
                'reason': reason,
                'status': status,
                'request_date': datetime.now().strftime("%Y-%m-%d")
            })
            flash('Permintaan cuti berhasil diajukan!', 'success')
        else:
            flash('Karyawan tidak ditemukan!', 'danger')
        return redirect(url_for('leave'))
    return render_template('leave/request.html', employees=all_employees)

@app.route('/leave/approve/<id>', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def approve_leave(id):
    leave_collection.update_one({'_id': ObjectId(id)}, {'$set': {'status': 'Disetujui'}})
    flash('Permintaan cuti disetujui!', 'success')
    return redirect(url_for('leave'))

@app.route('/leave/reject/<id>', methods=['POST'])
@login_required
@role_required('admin', 'manager')
def reject_leave(id):
    leave_collection.update_one({'_id': ObjectId(id)}, {'$set': {'status': 'Ditolak'}})
    flash('Permintaan cuti ditolak!', 'danger')
    return redirect(url_for('leave'))

# --- Penggajian ---
@app.route('/payroll')
@login_required
@role_required('admin', 'manager')
def payroll():
    all_payroll_records = list(payroll_collection.find())
    return render_template('payroll/list.html', payroll_records=all_payroll_records)

@app.route('/payroll/generate', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager')
def generate_payroll():
    all_employees = list(employees_collection.find())
    if request.method == 'POST':
        employee_id = request.form['employee_id']
        basic_salary = float(request.form['basic_salary'])
        allowances = float(request.form.get('allowances', 0))
        deductions = float(request.form.get('deductions', 0))
        net_salary = basic_salary + allowances - deductions
        pay_date = datetime.now().strftime("%Y-%m-%d")

        employee = employees_collection.find_one({'_id': ObjectId(employee_id)})
        if employee:
            payroll_collection.insert_one({
                'employee_id': ObjectId(employee_id),
                'employee_name': employee['name'],
                'basic_salary': basic_salary,
                'allowances': allowances,
                'deductions': deductions,
                'net_salary': net_salary,
                'pay_date': pay_date
            })
            flash(f'Gaji untuk {employee["name"]} berhasil digenerate!', 'success')
        else:
            flash('Karyawan tidak ditemukan!', 'danger')
        return redirect(url_for('payroll'))
    return render_template('payroll/generate.html', employees=all_employees)

# --- Proyek ---
@app.route('/projects')
@login_required
@role_required('admin', 'manager', 'employee')
def projects():
    all_projects = list(projects_collection.find())
    return render_template('projects/list.html', projects=all_projects)

@app.route('/projects/add', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager')
def add_project():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        status = request.form['status']
        projects_collection.insert_one({'name': name, 'description': description, 'status': status, 'start_date': datetime.now().strftime("%Y-%m-%d")})
        flash('Proyek berhasil ditambahkan!', 'success')
        return redirect(url_for('projects'))
    return render_template('projects/add.html')

@app.route('/projects/edit/<id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager')
def edit_project(id):
    project = projects_collection.find_one({'_id': ObjectId(id)})
    if not project:
        flash('Proyek tidak ditemukan!', 'danger')
        return redirect(url_for('projects'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        status = request.form['status']
        projects_collection.update_one(
            {'_id': ObjectId(id)},
            {'$set': {'name': name, 'description': description, 'status': status}}
        )
        flash('Data proyek berhasil diperbarui!', 'success')
        return redirect(url_for('projects'))
    return render_template('projects/edit.html', project=project)

@app.route('/projects/delete/<id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_project(id):
    projects_collection.delete_one({'_id': ObjectId(id)})
    flash('Proyek berhasil dihapus!', 'success')
    return redirect(url_for('projects'))

# --- Penjadwalan ---
@app.route('/scheduling')
@login_required
@role_required('admin', 'manager', 'employee')
def scheduling():
    all_schedules = list(scheduling_collection.find())
    return render_template('scheduling/list.html', schedules=all_schedules)

@app.route('/scheduling/add', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'manager')
def add_schedule():
    all_employees = list(employees_collection.find())
    all_projects = list(projects_collection.find())
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        scheduled_date = request.form['scheduled_date']
        employee_id = request.form.get('employee_id')
        project_id = request.form.get('project_id')

        schedule_data = {
            'title': title,
            'description': description,
            'scheduled_date': scheduled_date,
            'created_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        if employee_id:
            employee = employees_collection.find_one({'_id': ObjectId(employee_id)})
            if employee:
                schedule_data['employee_id'] = ObjectId(employee_id)
                schedule_data['employee_name'] = employee['name']
        if project_id:
            project = projects_collection.find_one({'_id': ObjectId(project_id)})
            if project:
                schedule_data['project_id'] = ObjectId(project_id)
                schedule_data['project_name'] = project['name']

        scheduling_collection.insert_one(schedule_data)
        flash('Jadwal berhasil ditambahkan!', 'success')
        return redirect(url_for('scheduling'))
    return render_template('scheduling/add.html', employees=all_employees, projects=all_projects)


# --- Pengaturan ---
@app.route('/settings')
@login_required
def settings():
    return render_template('settings/index.html')

@app.route('/settings/manage', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_settings():
    current_settings = app_settings_collection.find_one({})
    if not current_settings:
        current_settings = {'company_name': '', 'timezone': 'Asia/Jakarta'}

    if request.method == 'POST':
        company_name = request.form.get('company_name', '')
        timezone = request.form.get('timezone', 'Asia/Jakarta')

        app_settings_collection.update_one(
            {},
            {'$set': {'company_name': company_name, 'timezone': timezone}},
            upsert=True
        )
        flash('Pengaturan aplikasi berhasil diperbarui!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings/manage.html', settings=current_settings)

# --- User Management (Pengaturan) ---
@app.route('/settings/users')
@login_required
@role_required('admin')
def users_list():
    all_users = list(users_collection.find())
    return render_template('settings/users/list.html', users=all_users)

@app.route('/settings/users/add', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'employee')

        if users_collection.find_one({'username': username}):
            flash('Username sudah ada, pilih username lain.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            users_collection.insert_one({'username': username, 'password': hashed_password, 'role': role})
            flash('Pengguna berhasil ditambahkan!', 'success')
            return redirect(url_for('users_list'))
    return render_template('settings/users/add.html')

@app.route('/settings/users/edit/<id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(id):
    user_data = users_collection.find_one({'_id': ObjectId(id)})
    if not user_data:
        flash('Pengguna tidak ditemukan!', 'danger')
        return redirect(url_for('users_list'))

    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        
        existing_user = users_collection.find_one({'username': username})
        if existing_user and str(existing_user['_id']) != id:
            flash('Username sudah ada, pilih username lain.', 'danger')
            return render_template('settings/users/edit.html', user=user_data)

        update_data = {'username': username, 'role': role}
        new_password = request.form.get('password')
        if new_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            update_data['password'] = hashed_password

        users_collection.update_one(
            {'_id': ObjectId(id)},
            {'$set': update_data}
        )
        flash('Data pengguna berhasil diperbarui!', 'success')
        return redirect(url_for('users_list'))
    return render_template('settings/users/edit.html', user=user_data)

@app.route('/settings/users/delete/<id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(id):
    if current_user.id == id:
        flash('Anda tidak dapat menghapus akun Anda sendiri!', 'danger')
    else:
        users_collection.delete_one({'_id': ObjectId(id)})
        flash('Pengguna berhasil dihapus!', 'success')
    return redirect(url_for('users_list'))

# --- Integrasi (Pengaturan Baru) ---
@app.route('/settings/integrations', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_integrations():
    current_integrations = integrations_collection.find_one({})
    if not current_integrations:
        current_integrations = {
            'hris_api_key': '',
            'payroll_sync_enabled': False,
            'api_endpoint': ''
        }

    if request.method == 'POST':
        hris_api_key = request.form.get('hris_api_key', '')
        payroll_sync_enabled = 'payroll_sync_enabled' in request.form
        api_endpoint = request.form.get('api_endpoint', '')

        integrations_collection.update_one(
            {},
            {'$set': {
                'hris_api_key': hris_api_key,
                'payroll_sync_enabled': payroll_sync_enabled,
                'api_endpoint': api_endpoint
            }},
            upsert=True
        )
        flash('Pengaturan integrasi berhasil diperbarui!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings/integrations/manage.html', integrations=current_integrations)


if __name__ == '__main__':
    app.run(debug=True)
