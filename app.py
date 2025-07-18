import os
from flask import Flask, request, jsonify
from functools import wraps
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import NotFound, BadRequest, Forbidden
from dateutil import parser

# Impor dari file lokal
from database import db, init_db
from models import (
    User,
    Task,
    Project,
    StatusEnum,
    PriorityEnum,
    ProjectMember,
    ProjectRoleEnum,
)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
if not os.path.exists(INSTANCE_DIR):
    os.makedirs(INSTANCE_DIR)

# Inisialisasi Aplikasi Flask (tetap sama)
app = Flask(__name__)
app.config["SECRET_KEY"] = "kunci-task-management-api-uas"
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{os.path.join(INSTANCE_DIR, 'tasks.db')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Inisialisasi Database (tetap sama)
init_db(app)


# --- Penanganan Error Terpusat ---
@app.errorhandler(NotFound)
def handle_not_found(e):
    return jsonify(error=str(e).replace("404 Not Found: ", "")), 404


@app.errorhandler(BadRequest)
def handle_bad_request(e):
    return jsonify(error=str(e).replace("400 Bad Request: ", "")), 400


@app.errorhandler(Forbidden)
def handle_forbidden(e):
    return jsonify(error="You do not have permission to perform this action."), 403


def get_user_role_in_project(user_id, project_id):
    membership = ProjectMember.query.filter_by(
        user_id=user_id, project_id=project_id
    ).first()
    return membership.role if membership else None


def project_admin_required(f):
    @wraps(f)
    def decorated_function(current_user, project_id, *args, **kwargs):
        role = get_user_role_in_project(current_user.id, project_id)
        if role != ProjectRoleEnum.ADMIN:
            raise Forbidden("Project admin access is required.")
        return f(current_user, project_id=project_id, *args, **kwargs)

    return decorated_function


# --- Middleware Otentikasi Token ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token is missing!"}), 401
        if "Bearer " not in token:
            return jsonify({"error": "Token is invalid!"}), 401
        try:
            token = token.replace("Bearer ", "", 1)
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.get(data["user_id"])
            if not current_user:
                raise Exception()
        except Exception as e:
            return jsonify({"error": "Token is invalid or expired!"}), 401
        return f(current_user, *args, **kwargs)

    return decorated


# --- Endpoint Otentikasi Pengguna ---
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    errors = {}
    if not data.get("name"):
        errors["name"] = "Name is required."
    if not data.get("email"):
        errors["email"] = "Email is required."
    if User.query.filter_by(email=data.get("email")).first():
        errors.setdefault("email", []).append("Email is already registered.")
    if not data.get("password") or len(data.get("password")) < 8:
        errors.setdefault("password", []).append(
            "Password must be at least 8 characters."
        )

    if errors:
        return jsonify(errors=errors), 422

    hashed_password = generate_password_hash(data["password"], method="pbkdf2:sha256")
    new_user = User(
        name=data["name"],
        email=data["email"],
        password_hash=hashed_password,
        avatar_url=data.get("avatar_url"),
    )
    db.session.add(new_user)
    db.session.commit()

    token = jwt.encode(
        {
            "user_id": new_user.id,
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=1),
        },
        app.config["SECRET_KEY"],
    )

    return (
        jsonify(
            {
                "message": "Registration successful",
                "access_token": token,
                "user": new_user.to_dict(),
            }
        ),
        201,
    )


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or not data.get("email") or not data.get("password"):
        return jsonify(error="Email and password are required"), 400

    user = User.query.filter_by(email=data["email"]).first()
    if not user or not check_password_hash(user.password_hash, data["password"]):
        return jsonify(error="Invalid email or password"), 401

    token = jwt.encode(
        {
            "user_id": user.id,
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=1),
        },
        app.config["SECRET_KEY"],
    )

    return jsonify(
        {"message": "Login successful", "access_token": token, "user": user.to_dict()}
    )


# --- Endpoint Proyek ---
@app.route("/projects", methods=["GET"])
@token_required
def get_user_projects(current_user):
    # current_user.memberships didapat dari relasi di model User
    project_list = [
        membership.project.to_summary_dict(current_user.id)
        for membership in current_user.memberships
    ]
    return jsonify(project_list)


@app.route("/projects", methods=["POST"])
@token_required
def create_project(current_user):
    data = request.get_json()
    if not data or not data.get("name"):
        raise BadRequest("Project name is required.")

    new_project = Project(
        name=data["name"], description=data.get("description"), owner_id=current_user.id
    )
    db.session.add(new_project)

    membership = ProjectMember(
        user=current_user, project=new_project, role=ProjectRoleEnum.ADMIN
    )
    db.session.add(membership)
    db.session.commit()
    return jsonify(new_project.to_kanban_dict()), 201


@app.route("/projects/<int:project_id>", methods=["GET"])
@token_required
def get_project_details(current_user, project_id):
    project = Project.query.get(project_id)
    if not project:
        raise NotFound(f"Project with ID {project_id} not found.")

    # Validasi keanggotaan
    if not get_user_role_in_project(current_user.id, project_id):
        raise Forbidden()
    return jsonify(project.to_kanban_dict())


@app.route("/projects/<int:project_id>/members", methods=["POST"])
@token_required
def add_project_member(current_user, project_id):
    project = Project.query.get(project_id)
    data = request.get_json()

    user_to_add = User.query.get(data.get("user_id"))
    if not user_to_add:
        raise NotFound(f"User with ID {data.get('user_id')} not found.")

    if get_user_role_in_project(user_to_add.id, project_id):
        raise BadRequest(f"User {user_to_add.name} is already a member.")

    role_str = data.get("role", "MEMBER").upper()
    try:
        role = ProjectRoleEnum[role_str]
    except KeyError:
        raise BadRequest("Invalid role. Use 'ADMIN' or 'MEMBER'.")

    new_membership = ProjectMember(user=user_to_add, project=project, role=role)
    db.session.add(new_membership)
    db.session.commit()
    return (
        jsonify(
            message=f"User {user_to_add.name} added to project {project.name} as {role.value}."
        ),
        200,
    )


@app.route("/projects/<int:project_id>/members/<int:member_id>", methods=["PUT"])
@token_required
@project_admin_required
def update_member_role(current_user, project_id, member_id):
    membership = ProjectMember.query.filter_by(
        user_id=member_id, project_id=project_id
    ).first()
    if not membership:
        raise NotFound(
            f"Membership with user_id {member_id} and project_id {project_id} not found."
        )

    # Admin tidak bisa mengubah peran pemilik proyek
    if membership.user.id == membership.project.owner_id:
        raise Forbidden("Cannot change the role of the project owner.")

    data = request.get_json()
    new_role_str = data.get("role", "").upper()
    if not new_role_str:
        raise BadRequest("Role is required.")
    try:
        membership.role = ProjectRoleEnum[new_role_str]
    except KeyError:
        raise BadRequest("Invalid role. Use 'ADMIN' or 'MEMBER'.")

    db.session.commit()
    return jsonify(
        message=f"Role for user {membership.user.name} updated to {membership.role.value}."
    )


@app.route("/projects/<int:project_id>/members/<int:member_id>", methods=["DELETE"])
@token_required
@project_admin_required
def remove_project_member(current_user, project_id, member_id):
    membership = ProjectMember.query.filter_by(
        user_id=member_id, project_id=project_id
    ).first()
    if not membership:
        raise NotFound(
            f"Membership with user_id {member_id} and project_id {project_id} not found."
        )

    if membership.user.id == current_user.id:
        raise Forbidden("You cannot remove yourself.")
    if membership.user.id == membership.project.owner_id:
        raise Forbidden("Cannot remove the project owner.")

    db.session.delete(membership)
    db.session.commit()
    return jsonify(
        message=f"User {membership.user.name} has been removed from the project."
    )


@app.route("/projects/<int:project_id>", methods=["PUT"])
@token_required
@project_admin_required
def update_project(current_user, project_id):
    """Memperbarui nama atau deskripsi proyek."""
    project = Project.query.get(project_id)
    data = request.get_json()

    if not data or ("name" not in data and "description" not in data):
        raise BadRequest("Request body must contain 'name' or 'description'.")

    if "name" in data:
        project.name = data["name"]
    if "description" in data:
        project.description = data["description"]

    db.session.commit()
    return jsonify(project.to_kanban_dict())


@app.route("/projects/<int:project_id>/tasks", methods=["GET"])
@token_required
def get_tasks_in_project(current_user, project_id):
    project = Project.query.get(project_id)
    if not project:
        raise NotFound(f"Project with ID {project_id} not found.")

    if not get_user_role_in_project(current_user.id, project.id):
        raise Forbidden("You must be a member of the project to view its tasks.")

    tasks = Task.query.filter_by(project_id=project.id).all()
    return jsonify([task.to_dict() for task in tasks])


# --- Endpoint Tugas ---
@app.route("/tasks", methods=["POST"])
@token_required
def create_task(current_user):
    data = request.get_json()
    project_id = data.get("project_id")
    project = Project.query.get(project_id)
    if not project:
        raise NotFound(f"Project with ID {project_id} not found.")

    if current_user not in project.members:
        raise Forbidden("You must be a member of the project to add tasks.")

    new_task = Task(
        project_id=project_id,
        title=data.get("title"),
        description=data.get("description"),
        status=StatusEnum[data.get("status", "TODO").upper().replace(" ", "_")],
        priority=PriorityEnum[data.get("priority", "MEDIUM").upper()],
        assignee_id=data.get("assignee_id"),
    )
    if data.get("due_date"):
        new_task.due_date = parser.isoparse(data["due_date"])

    db.session.add(new_task)
    db.session.commit()
    return jsonify(new_task.to_dict()), 201


@app.route("/tasks/<int:task_id>", methods=["GET"])
@token_required
def get_task_details(current_user, task_id):
    task = Task.query.get(task_id)
    if not task:
        raise NotFound(f"Task with ID {task_id} not found.")

    if not get_user_role_in_project(current_user.id, task.project_id):
        raise Forbidden("You do not have permission to view this task.")

    return jsonify(task.to_dict())


@app.route("/tasks/<int:task_id>", methods=["PUT"])
@token_required
def update_task(current_user, task_id):
    task = Task.query.get(task_id)
    if not task:
        raise NotFound(f"Tugas dengan ID {task_id} tidak ditemukan")

    if current_user not in task.project.members:
        raise Forbidden("You must be a member of the project to update tasks.")

    data = request.get_json()
    for key, value in data.items():
        if key == "status":
            task.status = StatusEnum[value.upper().replace(" ", "_")]
        elif key == "priority":
            task.priority = PriorityEnum[value.upper()]
        elif key == "due_date":
            task.due_date = parser.isoparse(value) if value else None
        elif hasattr(task, key):
            setattr(task, key, value)

    db.session.commit()
    return jsonify(task.to_dict())


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
@token_required
def delete_task(current_user, task_id):
    task = Task.query.get(task_id)
    if not task:
        raise NotFound(f"Tugas dengan ID {task_id} tidak ditemukan")
    if current_user not in task.project.members:
        raise Forbidden("You must be a member of the project to delete tasks.")

    db.session.delete(task)
    db.session.commit()
    return jsonify(message="Tugas berhasil dihapus")


if __name__ == "__main__":
    if not os.path.exists("instance"):
        os.makedirs("instance")
    app.run(debug=True)
