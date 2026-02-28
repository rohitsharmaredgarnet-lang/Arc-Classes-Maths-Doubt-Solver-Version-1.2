from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from pydantic import BaseModel, Field
import sympy as sp
import os
import re

import models, schemas, auth, database
from database import engine

models.Base.metadata.create_all(bind=engine)

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Initialize Rate Limiter (e.g., max 30 requests per minute per IP)
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Arc Classes Doubt Solver API")

# Add Rate Limiter to App
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Robust Security: CORS and strict headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to your actual domain
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Ensure static directory exists
os.makedirs("static", exist_ok=True)

class SolveRequest(BaseModel):
    expression: str = Field(..., max_length=500) # Prevent massive payloads
    angle_mode: str = "deg"
    calc_mode: str = "solve" # "solve" or "eval"

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<html><body><h1>index.html not found in static folder</h1></body></html>"

app.mount("/static", StaticFiles(directory="static"), name="static")

# --- AUTH & ADMIN ROUTES ---
@app.post("/register", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(database.get_db)):
    db_user = auth.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, is_admin=False)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=schemas.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    user = auth.get_user_by_username(db, form_data.username)
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.is_banned:
        raise HTTPException(status_code=400, detail="User is banned: Contact Admin.")
    
    access_token_expires = timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=schemas.User)
def read_users_me(current_user: models.User = Depends(auth.get_current_active_user)):
    return current_user

@app.get("/admin/users")
def get_all_users(db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not permitted")
    users = db.query(models.User).all()
    # Safely omit hashes
    return [{"id": u.id, "username": u.username, "is_admin": u.is_admin, "is_banned": u.is_banned} for u in users]

@app.post("/admin/ban/{user_id}")
def toggle_ban_user(user_id: int, db: Session = Depends(database.get_db), current_user: models.User = Depends(auth.get_current_active_user)):
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Not permitted")
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_admin:
        raise HTTPException(status_code=400, detail="Cannot ban another admin")
    
    user.is_banned = not user.is_banned
    db.commit()
    return {"success": True, "user_id": user.id, "is_banned": user.is_banned}

# --- SOLVER ROUTE ---

@app.post("/solve")
@limiter.limit("30/minute") # Throttle requests
async def solve_math(request: Request, req: SolveRequest):
    expr_str = req.expression.strip()
    if not expr_str:
        return {"success": False, "error": "Empty Expression", "details": "Please provide an expression."}

    # Security: Strict Regex to ensure we only process math-like strings
    # Allow letters, numbers, basic operators, parens, decimal, equals sign
    if not re.match(r'^[a-zA-Z0-9+\-*/().,=\s^]*$', expr_str):
        return {"success": False, "error": "Invalid Characters", "details": "Expression contains unauthorized characters."}

    steps = []
    
    try:
        steps.append({
            "title": "Parsing Input",
            "body": f"Analyzing input securely with SymPy: <br><span class=\"math-hl\">{expr_str}</span>"
        })
        
        # Prepare for SymPy
        expr_str = expr_str.replace("^", "**")
        
        mode = req.calc_mode.lower()

        if mode == "solve":
            if "=" not in expr_str:
                return {
                    "success": False, 
                    "error": "Missing Equals Sign", 
                    "details": "When in 'Solve' mode, you must provide an equation with an '=' sign (e.g., 2*x + 5 = 15)."
                }

            left_str, right_str = expr_str.split("=", 1)
            left_expr = sp.sympify(left_str)
            right_expr = sp.sympify(right_str)
            equation = sp.Eq(left_expr, right_expr)
            
            vars_found = equation.free_symbols
            if not vars_found:
                # Formula evaluated perfectly with numbers
                steps.append({
                    "title": "Equation Verification",
                    "body": "No unknown variables found. Evaluating both sides to determine if the statement is True or False."
                })
                lhs_val = left_expr.evalf()
                rhs_val = right_expr.evalf()
                is_true = abs(lhs_val - rhs_val) < 1e-9 # Float math protection
                
                steps.append({
                    "title": "Final Result",
                    "body": f"Left Side: {lhs_val}<br>Right Side: {rhs_val}<br><div class=\"math-final\">Statement is {is_true}</div>"
                })
                return {"success": True, "answer": str(is_true), "steps": steps}

            if len(vars_found) > 1:
                return {
                    "success": False, 
                    "error": "Multiple Variables", 
                    "details": f"Multiple unknown variables found ({', '.join([str(v) for v in vars_found])}). To solve, replace all but one with numbers."
                }
            
            target_var = list(vars_found)[0]
            
            steps.append({
                "title": "Equation Setup",
                "body": f"Setting up the algebraic equation to solve for <strong>{target_var}</strong>:<br><span class=\"math-hl\">{sp.pretty(equation, use_unicode=True)}</span>"
            })
            
            steps.append({
                "title": "Algebraic Isolation",
                "body": f"Isolating the unknown variable <strong>{target_var}</strong> on one side..."
            })
            
            solution = sp.solve(equation, target_var)
            
            if len(solution) > 0:
                ans_list = []
                for s in solution:
                    val = s.evalf() if hasattr(s, 'evalf') else s
                    if getattr(val, 'is_real', False):
                        ans_list.append(str(round(float(val), 8)))
                    else:
                        ans_list.append(str(val))
                        
                final_ans = " or ".join(ans_list)
                
                steps.append({
                    "title": "Final Result",
                    "body": f"Calculation complete:<br><div class=\"math-final\">{target_var} = {final_ans}</div>"
                })
                
                return {"success": True, "answer": final_ans, "steps": steps}
            else:
                 # It might be an identity formula (e.g. `(x+1)^2 = x^2+2x+1`)
                 simplified_eq = sp.simplify(left_expr - right_expr) == 0
                 if simplified_eq:
                     ans_text = "All Real Numbers (Identity)"
                     steps.append({
                         "title": "Identity Found",
                         "body": f"This equation simplifies perfectly. This is an algebraic identity:<br><div class=\"math-final\">{target_var} can be any real number</div>"
                     })
                     return {"success": True, "answer": ans_text, "steps": steps}

                 return {"success": False, "error": "No Solution", "details": "The equation has no mathematical solution."}
        
        elif mode == "eval":
            if "=" in expr_str:
                left_str, right_str = expr_str.split("=", 1)
                left_expr = sp.sympify(left_str)
                right_expr = sp.sympify(right_str)
                
                steps.append({
                    "title": "Dual Expression Parsing",
                    "body": f"Equation detected inside Evaluation Mode. Evaluating left side and right side independently to display results."
                })
                
                lhs_eval = left_expr.evalf()
                rhs_eval = right_expr.evalf()
                
                final_html = f"LHS = {round(float(lhs_eval), 8) if getattr(lhs_eval, 'is_real', False) else str(lhs_eval)}<br>RHS = {round(float(rhs_eval), 8) if getattr(rhs_eval, 'is_real', False) else str(rhs_eval)}"
                
                steps.append({
                    "title": "Final Calculation",
                    "body": f"<div class=\"math-final\">{final_html}</div>"
                })
                
                return {"success": True, "answer": "Evaluated", "steps": steps}

            # simple evaluation
            expr_obj = sp.sympify(expr_str)
            steps.append({
                "title": "Expression Parsing",
                "body": f"Expression securely parsed:<br><span class=\"math-hl\">{sp.pretty(expr_obj, use_unicode=True)}</span>"
            })

            # Check for evaluation
            evaluated = expr_obj.evalf()
            if getattr(evaluated, 'is_real', False):
                ans = round(float(evaluated), 8)
            else:
                ans = str(evaluated)
                
            steps.append({
                "title": "Final Calculation",
                "body": f"Evaluating remaining expression...<br><div class=\"math-final\">{ans}</div>"
            })
            
            return {"success": True, "answer": str(ans), "steps": steps}

        else:
             return {"success": False, "error": "Invalid Mode", "details": "Calculation mode must be 'solve' or 'eval'."}

    except Exception as e:
        return {"success": False, "error": "Syntax Error", "details": str(e)}

if __name__ == "__main__":
    import uvicorn
    # Make sure to run the server if user executes main.py directly
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
