from database import db
from sqlalchemy.orm import relationship
from collections import defaultdict
import enum


class ProjectRoleEnum(enum.Enum):
    ADMIN = "Admin"
    MEMBER = "Member"


class StatusEnum(enum.Enum):
    TODO = "To-Do"
    IN_PROGRESS = "In Progress"
    DONE = "Done"


class PriorityEnum(enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class ProjectMember(db.Model):
    __tablename__ = "project_members"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), primary_key=True)
    role = db.Column(
        db.Enum(ProjectRoleEnum), nullable=False, default=ProjectRoleEnum.MEMBER
    )

    user = relationship("User", back_populates="memberships")
    project = relationship("Project", back_populates="memberships")


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar_url = db.Column(db.String(255), nullable=True)

    memberships = relationship(
        "ProjectMember", back_populates="user", cascade="all, delete-orphan"
    )

    def to_dict(self, include_email=True):
        user_dict = {"id": self.id, "name": self.name, "avatar_url": self.avatar_url}
        if include_email:
            user_dict["email"] = self.email
        return user_dict


class Project(db.Model):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    owner = relationship("User")
    tasks = relationship("Task", back_populates="project", cascade="all, delete-orphan")

    memberships = relationship(
        "ProjectMember", back_populates="project", cascade="all, delete-orphan"
    )

    @property
    def members(self):
        return [membership.user for membership in self.memberships]

    def to_kanban_dict(self):
        columns = defaultdict(list)
        for task in self.tasks:
            columns[task.status.value].append(task.to_dict())

        members_data = []
        for membership in self.memberships:
            member_info = membership.user.to_dict(include_email=False)
            member_info["role"] = membership.role.value
            members_data.append(member_info)

        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner": {"id": self.owner.id, "name": self.owner.name},
            "members": members_data,
            "columns": columns,
        }

    def to_summary_dict(self, user_id):
        membership = db.session.get(ProjectMember, (user_id, self.id))
        user_role = membership.role.value if membership else None

        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "owner_id": self.owner_id,
            "your_role": user_role,
        }


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.Enum(StatusEnum), default=StatusEnum.TODO, nullable=False)
    priority = db.Column(
        db.Enum(PriorityEnum), default=PriorityEnum.MEDIUM, nullable=False
    )
    due_date = db.Column(db.DateTime(timezone=True), nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    project = relationship("Project", back_populates="tasks")
    assignee = relationship("User")

    def to_dict(self):
        formatted_due_date = (
            self.due_date.isoformat().replace("+00:00", "Z") if self.due_date else None
        )
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority.value,
            "due_date": formatted_due_date,
            "assignee": (
                self.assignee.to_dict(include_email=False) if self.assignee else None
            ),
        }
