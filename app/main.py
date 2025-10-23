import os, hashlib
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for, session, abort
)
from sqlalchemy import (
    create_engine, select, func, ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session
from sqlalchemy.exc import IntegrityError

# werkzeug para hash de senha (PBKDF2-SHA256 por padrão)
from werkzeug.security import generate_password_hash, check_password_hash


# -------- Config --------
BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "dev-unsafe")

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,  # True em produção (HTTPS)
)
app.secret_key = SECRET_KEY

# -------- DB / Models --------
class Base(DeclarativeBase): ...
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True, index=True)
    password_hash: Mapped[str]
    enabled: Mapped[bool] = mapped_column(default=True)
    is_admin: Mapped[bool] = mapped_column(default=False)

class Election(Base):
    __tablename__ = "elections"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]
    candidates: Mapped[list["Candidate"]] = relationship(
        back_populates="election", cascade="all, delete-orphan"
    )

class Candidate(Base):
    __tablename__ = "candidates"
    id: Mapped[int] = mapped_column(primary_key=True)
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"))
    name: Mapped[str]
    election: Mapped[Election] = relationship(back_populates="candidates")

class Vote(Base):
    __tablename__ = "votes"
    id: Mapped[int] = mapped_column(primary_key=True)
    election_id: Mapped[int] = mapped_column(ForeignKey("elections.id"), index=True)
    candidate_id: Mapped[int] = mapped_column(ForeignKey("candidates.id"))
    voter_hash: Mapped[str] = mapped_column(index=True)
    __table_args__ = (
        # Impede dois votos com o mesmo hash na mesma eleição (dup submit / voto repetido)
        UniqueConstraint("election_id", "voter_hash", name="uq_election_voterhash"),
    )

engine = create_engine(DATABASE_URL, echo=False, future=True)
Base.metadata.create_all(engine)

# -------- Helpers --------
def db_sess():
    return Session(engine)

def get_current_user(db: Session) -> User | None:
    uid = session.get("user_id")
    return db.get(User, uid) if uid else None

def require_login(db: Session) -> User:
    u = get_current_user(db)
    if not u: abort(401)
    if not u.enabled: abort(403)
    return u

def require_admin(db: Session) -> User:
    u = get_current_user(db)
    if not u.is_admin: abort(403)
    return u

# Hash e verificação com werkzeug (PBKDF2-SHA256)
def password_hash(pw: str) -> str:
    # padrão: method="pbkdf2:sha256", salt_length=16
    return generate_password_hash(pw)

def verify_password(pw: str, ph: str) -> bool:
    return check_password_hash(ph, pw)

# Voter commitment: inclui senha + user_id + election_id
# (só é calculado no POST, após o usuário informar a senha)
def vote_commitment(password: str, user_id: int, election_id: int) -> str:
    material = f"{password}:{user_id}:{election_id}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()

# -------- Routes --------
@app.get("/")
def home():
    return redirect(url_for("login_page"))

# -- Registro --
@app.get("/register")
def register_page():
    return render_template("register.html", error=None)

@app.post("/register")
def register_submit():
    username = request.form.get("username","").strip()
    password = request.form.get("password","")
    confirm  = request.form.get("confirm","")

    if not username or not password:
        return render_template("register.html", error="Missing username or password")
    if password != confirm:
        return render_template("register.html", error="Passwords do not match")
    if len(password) > 1024:
        return render_template("register.html", error="Password too long")

    with db_sess() as db:
        if db.scalar(select(User).where(User.username==username)):
            return render_template("register.html", error="Username already exists")
        db.add(User(
            username=username,
            password_hash=password_hash(password),
            enabled=False,
            is_admin=False
        ))
        db.commit()
    return redirect(url_for("login_page"))

# -- Login/Logout --
@app.get("/login")
def login_page():
    return render_template("login.html", error=None)

@app.post("/login")
def login_submit():
    username = request.form.get("username","").strip()
    password = request.form.get("password","")
    with db_sess() as db:
        u = db.scalar(select(User).where(User.username==username))
        if not u or not verify_password(password, u.password_hash):
            return render_template("login.html", error="Invalid credentials")
        session["user_id"] = u.id
        session["is_admin"] = u.is_admin
    return redirect(url_for("vote_page"))

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# -- Votar --
@app.get("/vote")
def vote_page():
    with db_sess() as db:
        user = require_login(db)
        elections = db.scalars(select(Election).order_by(Election.id)).all()
        for e in elections:
            e.candidates  # carrega relationship
        # NÃO marcamos eleições já votadas no GET (anonimato)
        return render_template(
            "vote.html",
            user=user,
            elections=elections,
            voted=set(),   # compat com template
            error=None,
            ok=None
        )

@app.post("/vote")
def vote_submit():
    password = request.form.get("password", "")

    with db_sess() as db:
        user = require_login(db)
        u = db.get(User, user.id)

        # 1) Senha
        if not verify_password(password, u.password_hash):
            elections = db.scalars(select(Election).order_by(Election.id)).all()
            for e in elections: e.candidates
            return render_template(
                "vote.html", user=user, elections=elections, voted=set(),
                error="Senha incorreta.", ok=None
            )

        # 2) Carrega TODAS as eleições visíveis na página
        elections = db.scalars(select(Election).order_by(Election.id)).all()
        for e in elections: e.candidates

        # 3) Checa obrigatoriedade: cada eleição deve ter um radio selecionado
        missing = []
        selections: dict[int, int] = {}  # election_id -> candidate_id
        for e in elections:
            key = f"e_{e.id}"
            cid = request.form.get(key)
            if not cid:
                missing.append(e.title)
            else:
                selections[e.id] = int(cid)

        if missing:
            return render_template(
                "vote.html", user=user, elections=elections, voted=set(),
                error="Você precisa votar em todas as eleições. Faltou selecionar em: "
                      + ", ".join(missing),
                ok=None
            )

        # 4) Processa votos (com validação de pertencimento e anti-duplicidade)
        inserted = 0
        for election_id, candidate_id in selections.items():
            # Valida candidato pertence à eleição
            cand = db.scalar(select(Candidate).where(
                Candidate.id == candidate_id,
                Candidate.election_id == election_id
            ))
            if not cand:
                return render_template(
                    "vote.html", user=user, elections=elections, voted=set(),
                    error=f"Seleção inválida para a eleição “{election_id}”.",
                    ok=None
                )

            # Gera hash do voto (após senha)
            vh = vote_commitment(password, user.id, election_id)

            # Checagem app-level (caso schema antigo não tenha UNIQUE)
            dup = db.scalar(select(Vote.id).where(
                Vote.election_id == election_id,
                Vote.voter_hash == vh
            ))
            if dup:
                return render_template(
                    "vote.html", user=user, elections=elections, voted=set(),
                    error=f"Você já votou na eleição “{cand.election.title}”.",
                    ok=None
                )

            db.add(Vote(election_id=election_id, candidate_id=candidate_id, voter_hash=vh))
            inserted += 1

        # 5) Commit com proteção a corrida/duplo clique
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return render_template(
                "vote.html", user=user, elections=elections, voted=set(),
                error="Você já votou em uma das eleições enviadas.",
                ok=None
            )

        if inserted == 0:
            return render_template(
                "vote.html", user=user, elections=elections, voted=set(),
                error="Nenhum voto válido foi enviado.",
                ok=None
            )

        return render_template(
            "vote.html", user=user, elections=elections, voted=set(),
            error=None, ok="Seu(s) voto(s) foi/foram computado(s)."
        )

# -- Admin --
@app.get("/admin")
def admin_page():
    with db_sess() as db:
        admin = require_admin(db)
        elections = db.scalars(select(Election).order_by(Election.id)).all()
        results = []
        for e in elections:
            rows = db.execute(
                select(Candidate.id, Candidate.name, func.count(Vote.id))
                .join(Vote, Vote.candidate_id==Candidate.id, isouter=True)
                .where(Candidate.election_id==e.id)
                .group_by(Candidate.id, Candidate.name)
                .order_by(Candidate.id)
            ).all()
            results.append((e, rows))
        return render_template("admin.html", admin=admin, results=results)


if __name__ == "__main__":
    app.run(debug=False)
