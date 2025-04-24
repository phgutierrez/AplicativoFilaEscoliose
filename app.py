from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
import sqlite3
import logging
import traceback
import os
import pandas as pd
import json
from functools import wraps
from dotenv import load_dotenv
from password_policy import validar_senha
from municipios_pb import MUNICIPIOS_PB
import secrets

# Importações dos novos módulos
from database import init_app, get_db, get_db_session, engine
from models import Base, Usuario, Paciente, Consulta, Operado, Agendamento
from redis_locks import Lock, with_lock
from sqlalchemy import text, or_, and_, desc, func

# Carregar variáveis de ambiente
load_dotenv()

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='app.log'
)
logger = logging.getLogger(__name__)

# Initialize Flask app and configurations
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_key_123')
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv(
    'WTF_CSRF_SECRET_KEY', 'csrf_key_123')
app.config['WTF_CSRF_ENABLED'] = True
app.config['DATABASE'] = os.getenv('SQLITE_PATH', 'fila_escoliose.db')

# Define temp directory
temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp')
os.makedirs(temp_dir, exist_ok=True)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Function to generate CSP nonce


def generate_nonce():
    if 'csp_nonce' not in g:
        g.csp_nonce = secrets.token_urlsafe(16)
    return g.csp_nonce

# Pass CSP nonce to templates


@app.context_processor
def inject_nonce():
    return {'csp_nonce': generate_nonce}


# Define CSP with correct format for nonce
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
    'style-src': ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "'unsafe-inline'"],
    'font-src': ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
    'img-src': ["'self'", "data:"]
}

# Initialize Talisman with updated config
talisman = Talisman(
    app,
    force_https=False,
    content_security_policy=csp,
    strict_transport_security=False
)

# Inicializar banco de dados
engine = init_app(app)

# Verificamos se é ambiente de produção para criar tabelas automaticamente
if os.environ.get('FLASK_ENV') != 'production':
    with app.app_context():
        # Verificar se o engine foi inicializado corretamente
        if engine is not None:
            logger.info("Creating database tables with SQLAlchemy")
            Base.metadata.create_all(bind=engine)
        else:
            logger.error("Database engine is None, cannot create tables!")

# Função para gerar arquivos temporários seguros


def get_temp_file_path(prefix='tmp', suffix=''):
    """Gera um caminho de arquivo temporário seguro"""
    import tempfile
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=temp_dir)
    os.close(fd)
    return path

# Função para limpar arquivos temporários (agora usando timeout)


def cleanup_temp_files():
    """Remove arquivos temporários antigos"""
    from cleanup_tasks import clean_temporary_files
    clean_temporary_files()

# Função de validação de dados


def validate_input(data):
    if not data or len(data.strip()) == 0:
        return False
    return True


def get_db_connection():
    """Função original para conexão com SQLite"""
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logger.error(f"Database connection error: {e}")
        raise

# Verificar se o usuário precisa trocar a senha temporária


@app.before_request
def check_password_change_required():
    if 'usuario' in session and request.endpoint not in ['logout', 'trocar_senha', 'static']:
        try:
            with get_db_connection() as conn:
                user = conn.execute(
                    "SELECT senha_temporaria FROM usuarios WHERE usuario = ?",
                    (session['usuario'],)
                ).fetchone()

                if user and user['senha_temporaria'] == 1:
                    flash(
                        "Você precisa alterar sua senha temporária antes de continuar.", "warning")
                    return redirect(url_for('trocar_senha'))
        except Exception as e:
            logger.error(f"Erro ao verificar senha temporária: {str(e)}")

# Modificação do decorator login_required


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if 'usuario' not in session:
            logger.warning(f"Unauthorized access attempt to {request.path}")
            flash('Por favor, faça login para acessar esta página.', 'error')
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    return wrapped


def get_all_active_patients():
    with get_db_connection() as conn:
        return conn.execute("""
            SELECT p.id, p.nome, p.nascimento, p.contato, p.municipio, p.medico_assistente,
                c.data AS ultima_consulta, c.escore AS escore, c.prioridade AS prioridade,
                (
                    SELECT data FROM consultas WHERE paciente_id = p.id ORDER BY id ASC LIMIT 1
                ) AS primeira_consulta,
                c.data_judicial,
                c.is_demanda_judicial
            FROM pacientes p
            JOIN consultas c ON c.paciente_id = p.id
            JOIN (
                SELECT paciente_id, MAX(id) as last_id 
                FROM consultas 
                GROUP BY paciente_id
            ) latest ON latest.paciente_id = p.id AND c.id = latest.last_id
            GROUP BY p.id
            ORDER BY 
                c.is_demanda_judicial DESC,
                c.data_judicial DESC,
                c.escore DESC, 
                c.data DESC
        """).fetchall()


def get_paginated_patients(per_page, offset):
    with get_db_connection() as conn:
        return conn.execute("""
            SELECT p.id, p.nome, p.nascimento, p.contato, p.municipio, p.medico_assistente,
                c.data AS ultima_consulta, c.escore AS escore, c.prioridade AS prioridade,
                (
                    SELECT data FROM consultas WHERE paciente_id = p.id ORDER BY id ASC LIMIT 1
                ) AS primeira_consulta
            FROM pacientes p
            JOIN consultas c ON c.paciente_id = p.id
            JOIN (
                SELECT paciente_id, MAX(id) as last_id 
                FROM consultas 
                GROUP BY paciente_id
            ) latest ON latest.paciente_id = p.id AND c.id = latest.last_id
            GROUP BY p.id
            ORDER BY escore DESC, ultima_consulta DESC
            LIMIT ? OFFSET ?
        """, (per_page, offset)).fetchall()


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']

        with get_db_connection() as conn:
            user = conn.execute(
                "SELECT * FROM usuarios WHERE usuario = ?",
                (usuario,)
            ).fetchone()

            if user and check_password_hash(user['senha'], senha):
                session['usuario'] = user['usuario']
                session['perfil'] = user['perfil']

                # Verificar se a senha é temporária
                if user['senha_temporaria'] == 1:
                    session['force_password_change'] = True
                    return redirect(url_for('trocar_senha'))

                return redirect(url_for('painel'))

            flash('Usuário ou senha inválidos')

    return render_template('login.html')


@app.route('/trocar_senha', methods=['GET', 'POST'])
def trocar_senha():
    if 'usuario' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # CSRF token is automatically validated by Flask-WTF
        nova_senha = request.form['nova_senha']
        confirma_senha = request.form['confirma_senha']

        if nova_senha != confirma_senha:
            flash("As senhas não conferem")
            return render_template('trocar_senha.html')

        valida, msg = validar_senha(nova_senha)
        if not valida:
            flash(msg)
            return render_template('trocar_senha.html')

        try:
            with get_db_connection() as conn:
                conn.execute("BEGIN TRANSACTION")
                conn.execute("""
                    UPDATE usuarios 
                    SET senha = ?, senha_temporaria = 0 
                    WHERE usuario = ?""",
                             (generate_password_hash(nova_senha), session['usuario']))
                conn.execute("COMMIT")

            session.pop('force_password_change', None)
            flash("Senha alterada com sucesso!")
            return redirect(url_for('painel'))
        except Exception as e:
            with get_db_connection() as conn:
                conn.execute("ROLLBACK")
            logger.error(f"Erro ao trocar senha: {str(e)}")
            flash("Erro ao trocar senha. Tente novamente.")
            return render_template('trocar_senha.html')

    return render_template('trocar_senha.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/painel')
@login_required
def painel():
    imprimir_todos = request.args.get('imprimir') == 'todos'

    if imprimir_todos:
        page = 1
        per_page = 9999
        pacientes = get_all_active_patients()
    else:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        offset = (page - 1) * per_page
        pacientes = get_paginated_patients(per_page, offset)

    with get_db_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM pacientes").fetchone()[0]

        # Contar o total de pacientes operados
        total_operados = conn.execute(
            "SELECT COUNT(*) FROM operados").fetchone()[0]

        # Contar o total de cada prioridade na base inteira usando subconsultas mais precisas
        alta_prioridade = conn.execute("""
            SELECT COUNT(DISTINCT p.id) FROM pacientes p
            JOIN consultas c ON p.id = c.paciente_id
            WHERE c.id IN (
                SELECT MAX(id) FROM consultas 
                GROUP BY paciente_id
            )
            AND c.prioridade = 'Alta Prioridade'
        """).fetchone()[0]

        intermediaria = conn.execute("""
            SELECT COUNT(DISTINCT p.id) FROM pacientes p
            JOIN consultas c ON p.id = c.paciente_id
            WHERE c.id IN (
                SELECT MAX(id) FROM consultas 
                GROUP BY paciente_id
            )
            AND c.prioridade = 'Prioridade Intermediária'
        """).fetchone()[0]

        eletiva = conn.execute("""
            SELECT COUNT(DISTINCT p.id) FROM pacientes p
            JOIN consultas c ON p.id = c.paciente_id
            WHERE c.id IN (
                SELECT MAX(id) FROM consultas 
                GROUP BY paciente_id
            )
            AND c.prioridade = 'Prioridade Eletiva'
        """).fetchone()[0]

    total_pages = (total + per_page - 1) // per_page

    # Calcular a posição inicial na lista completa
    posicao_inicial = (page - 1) * per_page + 1

    return render_template(
        "painel.html",
        pacientes=pacientes,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total=total,
        total_operados=total_operados,
        posicao_inicial=posicao_inicial,
        total_alta_prioridade=alta_prioridade,
        total_intermediaria=intermediaria,
        total_eletiva=eletiva,
        imprimir_todos=imprimir_todos
    )


@app.route('/arquivo', methods=['GET', 'POST'])
@login_required
def arquivo():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    offset = (page - 1) * per_page

    filtro_mes = request.form.get('mes')
    filtro_ano = request.form.get('ano')

    query_count = "SELECT COUNT(*) FROM operados WHERE 1=1"
    query = "SELECT * FROM operados WHERE 1=1"
    params = []

    if filtro_mes:
        query_condition = " AND substr(data_realizacao, 4, 2) = ?"
        query += query_condition
        query_count += query_condition
        params.append(f"{int(filtro_mes):02}")

    if filtro_ano:
        query_condition = " AND substr(data_realizacao, 7, 4) = ?"
        query += query_condition
        query_count += query_condition
        params.append(filtro_ano)

    with get_db_connection() as conn:
        total = conn.execute(query_count, params).fetchone()[0]
        pacientes = conn.execute(
            query + " ORDER BY data_realizacao DESC LIMIT ? OFFSET ?",
            params + [per_page, offset]
        ).fetchall()

    total_pages = (total + per_page - 1) // per_page

    # Adicionar a data atual para uso no template
    hoje = datetime.today()

    return render_template(
        "arquivo.html",
        pacientes=pacientes,
        filtro_mes=filtro_mes,
        filtro_ano=filtro_ano,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total=total,
        hoje=hoje  # Adicionando a variável hoje ao contexto
    )


@app.route('/realizar_cirurgia/<int:paciente_id>')
@login_required
def realizar_cirurgia(paciente_id):
    if session['perfil'] not in ['medico', 'admin']:  # Permitir ambos os perfis
        flash("Você não tem permissão para realizar esta operação.", "error")
        return redirect(url_for('painel'))

    with get_db_connection() as conn:
        try:
            conn.execute("BEGIN TRANSACTION")
            paciente = conn.execute(
                "SELECT nome, nascimento FROM pacientes WHERE id = ?", (paciente_id,)).fetchone()
            consulta = conn.execute("SELECT data, escore, prioridade FROM consultas WHERE paciente_id = ?",
                                    (paciente_id,)).fetchone()

            if not paciente or not consulta:
                conn.execute("ROLLBACK")
                flash("Paciente ou consulta não encontrados.")
                return redirect(url_for('painel'))

            data_realizacao = datetime.today().strftime('%d/%m/%Y')

            conn.execute("""
                INSERT INTO operados (nome, nascimento, data_consulta, escore, prioridade, data_realizacao)
                VALUES (?, ?, ?, ?, ?, ?)""",
                         (paciente[0], paciente[1], consulta[0], consulta[1], consulta[2], data_realizacao))

            conn.execute("DELETE FROM pacientes WHERE id = ?", (paciente_id,))
            conn.execute(
                "DELETE FROM consultas WHERE paciente_id = ?", (paciente_id,))
            conn.execute("COMMIT")
            flash("Cirurgia registrada com sucesso.")
        except Exception as e:
            conn.execute("ROLLBACK")
            logger.error(f"Erro ao realizar cirurgia: {str(e)}")
            flash(f"Erro ao realizar cirurgia: {str(e)}")

    return redirect(url_for('painel'))


@app.route('/exportar_ativos')
@login_required
def exportar_ativos():
    temp_file = get_temp_file_path(prefix='fila_ativos_', suffix='.xlsx')
    try:
        with get_db_connection() as conn:
            df = pd.read_sql_query("""
                SELECT p.nome, p.nascimento, c.data AS data_consulta,
                       c.escore, c.prioridade
                FROM pacientes p
                JOIN (
                    SELECT paciente_id, MAX(id) as last_id FROM consultas GROUP BY paciente_id
                ) ult ON ult.paciente_id = p.id
                JOIN consultas c ON c.id = ult.last_id
                WHERE p.id NOT IN (SELECT id FROM operados)""", conn)
        df.to_excel(temp_file, index=False)
        return send_file(temp_file, as_attachment=True, download_name="fila_ativos.xlsx")
    except Exception as e:
        logger.error(f"Erro ao exportar ativos: {str(e)}")
        flash("Erro ao exportar dados.")
        return redirect(url_for('painel'))
    finally:
        # O arquivo será removido posteriormente pela limpeza automática
        pass


@app.route('/exportar_operados')
@login_required
def exportar_operados():
    temp_file = get_temp_file_path(
        prefix='pacientes_operados_', suffix='.xlsx')
    try:
        with get_db_connection() as conn:
            df = pd.read_sql_query(
                "SELECT * FROM operados ORDER BY data_realizacao DESC", conn)
        df.to_excel(temp_file, index=False)
        return send_file(temp_file, as_attachment=True, download_name="pacientes_operados.xlsx")
    except Exception as e:
        logger.error(f"Erro ao exportar operados: {str(e)}")
        flash("Erro ao exportar dados.")
        return redirect(url_for('arquivo'))
    finally:
        # O arquivo será removido posteriormente pela limpeza automática
        pass


@app.route('/importar_planilha', methods=['GET', 'POST'])
@login_required
def importar_planilha():
    """Importa dados de uma planilha Excel"""
    if request.method == 'POST':
        file = request.files['arquivo']
        if not file or not file.filename.endswith('.xlsx'):
            flash("Arquivo inválido. Envie um .xlsx.")
            return redirect(url_for('importar_planilha'))

        try:
            temp_file = get_temp_file_path(prefix='import_', suffix='.csv')
            df = pd.read_excel(file)

            colunas_necessarias = [
                'PACIENTE', 'D.NASC', 'D.ATEND', 'GRAU', 'CONTATO', 'MUNICIPIO', 'MEDICO']
            for col in colunas_necessarias:
                if col not in df.columns:
                    flash(f"Coluna obrigatória ausente: {col}")
                    return redirect(url_for('importar_planilha'))

            df = df[colunas_necessarias].dropna(
                subset=['PACIENTE', 'D.NASC', 'GRAU'])
            df = df[pd.to_numeric(df['GRAU'], errors='coerce').notnull()]
            df['GRAU'] = df['GRAU'].astype(float)

            def cobb_valor(grau):
                if grau < 60:
                    return 1
                elif grau < 80:
                    return 2
                return 3

            df['ESCORE'] = df['GRAU'].apply(cobb_valor)
            df['PRIORIDADE'] = df['ESCORE'].apply(
                lambda x: 'Alta Prioridade' if x > 2 else (
                    'Prioridade Intermediária' if x == 2 else 'Prioridade Eletiva')
            )

            # Renomear colunas para padronizar
            df.rename(columns={
                'PACIENTE': 'nome',
                'D.NASC': 'nascimento',
                'D.ATEND': 'data_consulta',
                'CONTATO': 'contato',
                'MUNICIPIO': 'municipio',
                'MEDICO': 'medico_assistente'
            }, inplace=True)

            # Converter colunas de data para string antes da serialização
            if 'nascimento' in df.columns and df['nascimento'].dtype != 'object':
                df['nascimento'] = df['nascimento'].dt.strftime('%d/%m/%Y')
            if 'data_consulta' in df.columns and df['data_consulta'].dtype != 'object':
                df['data_consulta'] = df['data_consulta'].dt.strftime(
                    '%d/%m/%Y')

            # Armazena para próxima etapa (preview)
            df.to_csv(temp_file, index=False)
            dados = df.to_dict(orient='records')

            # Salvar dados em formato JSON
            temp_dir = os.path.join(os.path.dirname(
                os.path.abspath(__file__)), 'tmp')
            os.makedirs(temp_dir, exist_ok=True)

            import time
            import uuid

            temp_filename = f"import_{int(time.time())}_{uuid.uuid4().hex[:8]}.json"
            temp_file = os.path.join(temp_dir, temp_filename)

            # Salvar em JSON
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(dados, f, ensure_ascii=False)

            # Armazenar o caminho do arquivo na sessão
            session['temp_import_file'] = temp_file

            return render_template("preview_importar.html", dados=dados)

        except Exception as e:
            logger.error(f"Erro ao processar planilha: {str(e)}")
            flash(f"Erro ao processar planilha: {str(e)}")
            return redirect(url_for('importar_planilha'))

    return render_template("importar.html")


@app.route('/confirmar_importacao', methods=['POST'])
@login_required
def confirmar_importacao():
    """Confirma a importação de dados da planilha para o banco"""
    if session['perfil'] != 'admin':
        flash("Acesso restrito a administradores.", "error")
        return redirect(url_for('painel'))

    if 'temp_import_file' not in session:
        flash(
            "Sessão de importação expirada. Por favor, envie a planilha novamente.", "error")
        return redirect(url_for('importar_planilha'))

    temp_file = session['temp_import_file']
    if not os.path.exists(temp_file):
        flash("Arquivo temporário expirou. Por favor, carregue novamente.", "error")
        return redirect(url_for('importar_planilha'))

    conn = None  # Inicializa conn como None

    try:
        # Carregar dados do arquivo temporário usando json em vez de pickle
        with open(temp_file, 'r', encoding='utf-8') as f:
            dados = json.load(f)

        # Conecta ao banco de dados
        conn = get_db_connection()
        conn.execute("BEGIN TRANSACTION")
        count = 0

        for dado in dados:
            # Inserir o paciente INCLUINDO o campo versao=1
            cursor = conn.execute("""
                INSERT INTO pacientes (nome, nascimento, contato, municipio, medico_assistente, versao)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (
                dado['nome'],
                dado['nascimento'],
                # Usa get() com valor padrão para evitar KeyError
                dado.get('contato', ''),
                dado.get('municipio', ''),
                dado.get('medico_assistente', '')
            ))

            paciente_id = cursor.lastrowid
            count += 1

            # Inserir a consulta associada INCLUINDO o campo versao=1
            conn.execute("""
                INSERT INTO consultas (paciente_id, data, escore, prioridade, versao)
                VALUES (?, ?, ?, ?, 1)
            """, (
                paciente_id,
                dado['data_consulta'],
                dado.get('ESCORE', 0),
                dado.get('PRIORIDADE', 'Prioridade Eletiva')
            ))

        conn.execute("COMMIT")

        # Limpar recursos
        session.pop('temp_import_file', None)
        try:
            os.remove(temp_file)
        except:
            pass

        flash(f"{count} pacientes importados com sucesso!", "success")
        return redirect(url_for('painel'))

    except Exception as e:
        # Verifica se conn existe antes de tentar fazer rollback
        if conn is not None:
            try:
                conn.execute("ROLLBACK")
            except:
                pass

        logger.error(f"Erro na importação: {str(e)}")
        logger.error(traceback.format_exc())

        # Tentar limpar o arquivo temporário
        try:
            os.remove(temp_file)
        except:
            pass

        session.pop('temp_import_file', None)

        flash(f"Erro ao importar dados: {str(e)}", "error")
        return redirect(url_for('importar_planilha'))


@app.route('/atualizar_usuario/<int:user_id>', methods=['POST'])
@login_required
def atualizar_usuario(user_id):
    if session['perfil'] != 'admin':
        return redirect(url_for('painel'))

    nova_senha = request.form.get('nova_senha')
    novo_perfil = request.form.get('perfil')

    with get_db_connection() as conn:
        try:
            conn.execute("BEGIN TRANSACTION")

            if nova_senha and nova_senha.standp():
                # Validar a nova senha
                valida, msg = validar_senha(nova_senha)
                if not valida:
                    flash(msg)
                    return redirect(url_for('editar_usuarios'))

                # Gerar hash da nova senha
                hash_senha = generate_password_hash(nova_senha)

                # Atualizar perfil e senha
                conn.execute("""
                    UPDATE usuarios 
                    SET perfil = ?, senha = ?, senha_temporaria = 1
                    WHERE id = ?
                """, (novo_perfil, hash_senha, user_id))
                flash(
                    'Usuário atualizado com sucesso e nova senha definida como temporária.')
            else:
                # Atualizar apenas o perfil
                conn.execute("""
                    UPDATE usuarios 
                    SET perfil = ?
                    WHERE id = ?
                """, (novo_perfil, user_id))
                flash('Perfil de usuário atualizado com sucesso.')

            conn.execute("COMMIT")
        except Exception as e:
            conn.execute("ROLLBACK")
            logger.error(f"Erro ao atualizar usuário: {str(e)}")
            flash(f"Erro ao atualizar usuário: {str(e)}")

    return redirect(url_for('editar_usuarios'))


@app.route('/criar_usuario', methods=['GET', 'POST'])
@login_required
def criar_usuario():
    if session.get('perfil') != 'admin':
        flash("Acesso restrito ao administrador.")
        return redirect(url_for('painel'))

    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']
        perfil = request.form['perfil']

        # Validação básica
        if not usuario or not senha or not perfil:
            flash("Todos os campos são obrigatórios!")
            return render_template("criar_usuario.html")

        # Validação da senha
        valida, msg = validar_senha(senha)
        if not valida:
            flash(msg)
            return render_template("criar_usuario.html")

        with get_db_connection() as conn:
            try:
                conn.execute("BEGIN TRANSACTION")
                # Verificar se o usuário já existe
                existe = conn.execute(
                    "SELECT 1 FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
                if existe:
                    conn.execute("ROLLBACK")
                    flash("Usuário já existe!")
                    return render_template("criar_usuario.html")

                # Criar o novo usuário com senha temporária
                senha_hash = generate_password_hash(senha)
                conn.execute("""
                    INSERT INTO usuarios (usuario, senha, perfil, senha_temporaria) 
                    VALUES (?, ?, ?, ?)
                """, (usuario, senha_hash, perfil, 1))
                conn.execute("COMMIT")

                flash("Usuário criado com sucesso!")
                return redirect(url_for('editar_usuarios'))
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.error(f"Erro ao criar usuário: {str(e)}")
                flash(f"Erro ao criar usuário: {str(e)}")
                return render_template("criar_usuario.html")

    return render_template("criar_usuario.html")


@app.route('/editar_usuarios')
@login_required
def editar_usuarios():
    if session.get('perfil') != 'admin':
        flash("Acesso restrito.")
        return redirect(url_for('painel'))

    with get_db_connection() as conn:
        usuarios = conn.execute(
            "SELECT id, usuario, perfil FROM usuarios").fetchall()

    return render_template("editar_usuarios.html", usuarios=usuarios)


@app.route('/excluir_usuario/<int:user_id>')
@login_required
def excluir_usuario(user_id):
    if session.get('perfil') != 'admin':
        flash("Acesso restrito a administradores.")
        return redirect(url_for('painel'))

    # Verificar se o usuário não está tentando excluir a si mesmo
    with get_db_connection() as conn:
        usuario = conn.execute(
            "SELECT usuario FROM usuarios WHERE id = ?", (user_id,)).fetchone()

        if not usuario:
            flash("Usuário não encontrado.")
            return redirect(url_for('editar_usuarios'))

        if usuario['usuario'] == session['usuario']:
            flash("Você não pode excluir sua própria conta.")
            return redirect(url_for('editar_usuarios'))

        # Verificar se é o último administrador
        admin_count = conn.execute(
            "SELECT COUNT(*) FROM usuarios WHERE perfil = 'admin'").fetchone()[0]
        user_is_admin = conn.execute(
            "SELECT COUNT(*) FROM usuarios WHERE id = ? AND perfil = 'admin'", (user_id,)).fetchone()[0]

        if admin_count <= 1 and user_is_admin:
            flash("Não é possível excluir o último administrador do sistema.")
            return redirect(url_for('editar_usuarios'))

        try:
            conn.execute("BEGIN TRANSACTION")
            conn.execute("DELETE FROM usuarios WHERE id = ?", (user_id,))
            conn.execute("COMMIT")
            flash(f"Usuário '{usuario['usuario']}' excluído com sucesso.")
        except Exception as e:
            conn.execute("ROLLBACK")
            logger.error(f"Erro ao excluir usuário: {str(e)}")
            flash(f"Erro ao excluir usuário: {str(e)}")

    return redirect(url_for('editar_usuarios'))


@app.route('/limpar_base', methods=['POST'])
@login_required
def limpar_base():
    # Verifica se o usuário é administrador
    if session.get('perfil') != 'admin':
        flash('Você não tem permissão para realizar esta operação.', 'error')
        return redirect(url_for('painel'))

    try:
        with get_db_connection() as conn:
            conn.execute("DELETE FROM consultas")
            conn.execute("DELETE FROM pacientes")
            conn.commit()

        flash('Todos os dados foram removidos com sucesso.', 'success')
    except Exception as e:
        flash(f'Erro ao limpar a base de dados: {str(e)}', 'error')

    return redirect(url_for('painel'))


@app.route('/apagar_selecionados', methods=['POST'])
@login_required
def apagar_selecionados():
    # Verifica se o usuário é administrador
    if session.get('perfil') != 'admin':
        flash('Você não tem permissão para realizar esta operação.', 'error')
        return redirect(url_for('painel'))

    selecionados = request.form.getlist('selecionados')

    if not selecionados:
        flash('Nenhum paciente selecionado.', 'warning')
        return redirect(url_for('painel'))

    try:
        with get_db_connection() as conn:
            # Apagar as consultas relacionadas primeiro (integridade referencial)
            placeholders = ','.join(['?' for _ in selecionados])
            conn.execute(
                f"DELETE FROM consultas WHERE paciente_id IN ({placeholders})", selecionados)

            # Depois apagar os pacientes
            conn.execute(
                f"DELETE FROM pacientes WHERE id IN ({placeholders})", selecionados)
            conn.commit()

        flash(f'{len(selecionados)} pacientes removidos com sucesso.', 'success')
    except Exception as e:
        flash(f'Erro ao remover pacientes: {str(e)}', 'error')

    return redirect(url_for('painel'))


@app.route('/apagar_arquivo', methods=['POST'])
@login_required
def apagar_arquivo():
    if session.get('perfil') != 'admin':
        flash("Acesso restrito.")
        return redirect(url_for('arquivo'))

    acao = request.form.get('acao')

    with get_db_connection() as conn:
        try:
            conn.execute("BEGIN TRANSACTION")
            if acao == 'apagar_tudo':
                conn.execute("DELETE FROM operados")
                flash("Todos os dados foram apagados do arquivo.")
            elif acao == 'apagar_selecionados':
                selecionados = request.form.getlist('selecionados')
                if selecionados:
                    placeholders = ','.join(['?']*len(selecionados))
                    conn.execute(
                        f"DELETE FROM operados WHERE id IN ({placeholders})", selecionados)
                    flash("Pacientes selecionados apagados.")
                else:
                    flash("Nenhum paciente selecionado.")
            conn.execute("COMMIT")
        except Exception as e:
            conn.execute("ROLLBACK")
            logger.error(f"Erro ao apagar registros do arquivo: {str(e)}")
            flash(f"Erro ao apagar registros: {str(e)}")

    return redirect(url_for('arquivo'))


@app.route('/novo', methods=['GET', 'POST'])
@login_required
def novo():
    if session['perfil'] != 'medico' and session['perfil'] != 'admin':
        flash("Acesso restrito a médicos e administradores.")
        return redirect(url_for('painel'))

    if request.method == 'POST':
        nome = request.form['nome']
        nascimento = request.form['nascimento']
        contato = request.form['contato']
        municipio = request.form['municipio']

        # Correção: Trocar 'ou' por 'or'
        if not nome or not nascimento or not contato or not municipio:
            flash("Todos os campos são obrigatórios")
            return render_template("novo.html", municipios=MUNICIPIOS_PB)

        # Validação do município
        if municipio not in MUNICIPIOS_PB['todos']:
            flash('Município inválido')
            return render_template("novo.html", municipios=MUNICIPIOS_PB)

        medico_assistente = session['usuario']

        try:
            with get_db_connection() as conn:
                conn.execute("BEGIN TRANSACTION")
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO pacientes (nome, nascimento, contato, municipio, medico_assistente)
                    VALUES (?, ?, ?, ?, ?)
                """, (nome, nascimento, contato, municipio, medico_assistente))
                paciente_id = cur.lastrowid
                conn.execute("COMMIT")
                flash("Paciente cadastrado com sucesso!")
                return redirect(url_for('nova_consulta', paciente_id=paciente_id))
        except Exception as e:
            with get_db_connection() as conn:
                conn.execute("ROLLBACK")
            logger.error(f"Erro ao cadastrar paciente: {str(e)}")
            flash(f"Erro ao cadastrar paciente: {str(e)}")
            return render_template("novo.html", municipios=MUNICIPIOS_PB)

    # Adicionar a data atual para uso no template
    today = datetime.today()
    return render_template("novo.html", municipios=MUNICIPIOS_PB, today=today)


@app.route('/nova_consulta/<int:paciente_id>', methods=['GET', 'POST'])
@login_required
def nova_consulta(paciente_id):
    if session['perfil'] != 'medico' and session['perfil'] != 'admin':
        logger.warning(
            f"Unauthorized access attempt to nova_consulta by {session['usuario']}")
        flash("Acesso restrito a médicos e administradores.")
        return redirect(url_for('painel'))

    try:
        with get_db_connection() as conn:
            # Validação do paciente_id
            paciente = conn.execute(
                "SELECT id, nascimento FROM pacientes WHERE id = ?", (paciente_id,)).fetchone()
            if not paciente:
                logger.error(f"Invalid patient_id accessed: {paciente_id}")
                flash('Paciente não encontrado.', 'error')
                return redirect(url_for('painel'))

            if request.method == 'POST':
                # Validação dos dados do formulário
                dados = request.form
                try:
                    escore = sum([int(dados.get(campo, 0)) for campo in [
                        'tipo', 'cobb', 'progresso', 'idade_classe', 'risser',
                        'status', 'comorbidade', 'dor', 'tempo']])
                except ValueError:
                    flash('Dados inválidos no formulário.', 'error')
                    return redirect(url_for('nova_consulta', paciente_id=paciente_id))

                prioridade = ('Alta Prioridade' if escore > 15
                              else 'Prioridade Intermediária' if escore > 9
                              else 'Prioridade Eletiva')
                data_consulta = datetime.today().strftime('%d/%m/%Y')

                try:
                    conn.execute("BEGIN TRANSACTION")
                    conn.execute("""
                        INSERT INTO consultas (paciente_id, data, escore, prioridade)
                        VALUES (?, ?, ?, ?)""",
                                 (paciente_id, data_consulta, escore, prioridade))
                    conn.execute("COMMIT")
                    flash("Consulta registrada com sucesso!")
                    logger.info(
                        f"Nova consulta registrada para paciente {paciente_id}")
                except Exception as e:
                    conn.execute("ROLLBACK")
                    logger.error(f"Erro ao registrar consulta: {str(e)}")
                    flash(f"Erro ao registrar consulta: {str(e)}")

                return redirect(url_for('painel'))

            # PARTE GET: consultar histórico + calcular idade
            historico = conn.execute("""
                SELECT c.id, c.paciente_id, c.data, c.prioridade, c.escore
                FROM consultas c WHERE paciente_id = ? ORDER BY c.id DESC""",
                                     (paciente_id,)).fetchall()

            nascimento = paciente['nascimento']

            try:
                nascimento_dt = datetime.strptime(nascimento, "%d/%m/%Y")
            except ValueError:
                try:
                    nascimento_dt = datetime.strptime(nascimento, "%Y-%m-%d")
                except ValueError:
                    logger.error(
                        f"Invalid date format for patient {paciente_id}")
                    flash('Erro no formato da data de nascimento.', 'error')
                    return redirect(url_for('painel'))

            hoje = datetime.today()
            idade = hoje.year - nascimento_dt.year - (
                (hoje.month, hoje.day) < (nascimento_dt.month, nascimento_dt.day)
            )

            faixa = "2" if idade <= 10 else "1" if idade <= 14 else "0"

            return render_template(
                "nova_consulta.html",
                historico=historico,
                idade=idade,
                faixa=faixa
            )

    except Exception as e:
        logger.error(f"Error in nova_consulta: {str(e)}")
        flash('Ocorreu um erro ao processar sua requisição.', 'error')
        return redirect(url_for('painel'))


@app.route('/agendar_cirurgia', methods=['POST'])
@login_required
def agendar_cirurgia():
    """Agendar cirurgia para um paciente"""
    if not request.is_json:
        return jsonify({'erro': 'Requisição inválida'}), 400

    data = request.get_json()
    logger.info(f"Dados recebidos para agendamento: {data}")

    paciente_id = data.get('paciente_id')
    data_cirurgia = data.get('data_cirurgia')

    # Validar e converter os dados recebidos
    try:
        paciente_id = int(paciente_id)
    except (ValueError, TypeError):
        logger.error(f"ID de paciente inválido: {paciente_id}")
        return jsonify({'erro': 'ID de paciente inválido'}), 400

    if not paciente_id or not data_cirurgia:
        logger.error("Dados incompletos: paciente_id ou data_cirurgia ausente")
        return jsonify({'erro': 'Dados incompletos'}), 400

    try:
        with get_db_connection() as conn:
            # Verificar se o paciente existe
            paciente = conn.execute(
                'SELECT id, nome FROM pacientes WHERE id = ?', (paciente_id,)).fetchone()
            if not paciente:
                logger.error(f"Paciente não encontrado: {paciente_id}")
                return jsonify({'erro': 'Paciente não encontrado'}), 404

            # Formatar a data corretamente para o banco de dados
            try:
                # Converter yyyy-mm-dd para dd/mm/yyyy
                data_formatada = datetime.strptime(
                    data_cirurgia, '%Y-%m-%d').strftime('%d/%m/%Y')
                logger.info(f"Data formatada: {data_formatada}")
            except ValueError:
                logger.error(f"Formato de data inválido: {data_cirurgia}")
                return jsonify({'erro': 'Formato de data inválido'}), 400

            # Verificar se já existe agendamento para este paciente
            agendamento_existente = conn.execute(
                'SELECT id FROM agendamentos WHERE paciente_id = ? AND realizado = 0',
                (paciente_id,)
            ).fetchone()

            if agendamento_existente:
                # Atualizar o agendamento existente
                conn.execute(
                    'UPDATE agendamentos SET data_cirurgia = ? WHERE paciente_id = ? AND realizado = 0',
                    (data_formatada, paciente_id)
                )
                logger.info(
                    f"Agendamento atualizado para paciente {paciente_id}")
            else:
                # Inserir novo agendamento
                conn.execute(
                    'INSERT INTO agendamentos (paciente_id, data_cirurgia, realizado) VALUES (?, ?, 0)',
                    (paciente_id, data_formatada)
                )
                logger.info(
                    f"Novo agendamento criado para paciente {paciente_id}")

            conn.commit()

            # Registrar atividade no log
            logger.info(
                f"Cirurgia agendada com sucesso para o paciente (ID: {paciente_id}) para {data_formatada}")

            return jsonify({'sucesso': True, 'mensagem': 'Cirurgia agendada com sucesso'}), 200

    except Exception as e:
        logger.error(f"Erro ao agendar cirurgia: {str(e)}")
        logger.error(traceback.format_exc())  # Log do traceback completo
        return jsonify({'erro': f'Erro ao agendar cirurgia: {str(e)}'}), 500


@app.route('/agenda')
@login_required
def agenda():
    """Exibe a página de agenda das cirurgias"""
    try:
        with get_db_connection() as conn:
            agendamentos = conn.execute('''
                SELECT a.id, a.data_cirurgia, p.id as paciente_id, 
                       p.nome, p.nascimento, p.contato, p.municipio, 
                       c.escore, c.prioridade
                FROM agendamentos a
                JOIN pacientes p ON a.paciente_id = p.id
                JOIN consultas c ON p.id = c.paciente_id
                JOIN (
                    SELECT paciente_id, MAX(id) as last_id FROM consultas GROUP BY paciente_id
                ) latest ON latest.paciente_id = p.id AND c.id = latest.last_id
                WHERE a.realizado = 0
                ORDER BY a.data_cirurgia ASC
            ''').fetchall()

        return render_template('agenda.html', agendamentos=agendamentos)
    except Exception as e:
        logger.error(f"Erro ao carregar agenda: {str(e)}")
        flash(f"Erro ao carregar agenda: {str(e)}")
        return redirect(url_for('painel'))


@app.route('/cancelar_agendamento/<int:agendamento_id>')
@login_required
def cancelar_agendamento(agendamento_id):
    """Cancela o agendamento de uma cirurgia"""
    # Verificar se o usuário tem permissão
    if session['perfil'] not in ['medico', 'admin', 'gestor']:
        flash("Você não tem permissão para cancelar agendamentos.", "error")
        return redirect(url_for('agenda'))

    try:
        with get_db_connection() as conn:
            # Verificar se o agendamento existe
            agendamento = conn.execute(
                'SELECT id FROM agendamentos WHERE id = ?',
                (agendamento_id,)
            ).fetchone()

            if not agendamento:
                flash("Agendamento não encontrado.", "error")
                return redirect(url_for('agenda'))

            # Excluir o agendamento
            conn.execute('DELETE FROM agendamentos WHERE id = ?',
                         (agendamento_id,))
            conn.commit()

            # Registrar atividade no log
            logger.info(f"Agendamento cancelado (ID: {agendamento_id})")

            flash("Agendamento cancelado com sucesso.", "success")

    except Exception as e:
        logger.error(f"Erro ao cancelar agendamento: {str(e)}")
        flash(f"Erro ao cancelar agendamento: {str(e)}", "error")

    return redirect(url_for('agenda'))


@app.route('/cancelar_realizacao/<int:operado_id>')
@login_required
def cancelar_realizacao(operado_id):
    """Cancela a realização da cirurgia e devolve o paciente para a lista de ativos"""
    # Verificar se o usuário tem permissão
    if session['perfil'] not in ['medico', 'admin']:
        flash("Você não tem permissão para cancelar realizações de cirurgia.", "error")
        return redirect(url_for('arquivo'))

    try:
        with get_db_connection() as conn:
            # Verificar se o registro existe
            operado = conn.execute(
                'SELECT id, nome, nascimento, data_consulta, escore, prioridade FROM operados WHERE id = ?',
                (operado_id,)
            ).fetchone()

            if not operado:
                flash("Registro não encontrado.", "error")
                return redirect(url_for('arquivo'))

            # Começar transação
            conn.execute("BEGIN TRANSACTION")

            # 1. Inserir paciente de volta na tabela de pacientes
            cur = conn.cursor()
            cur.execute(
                # Adicionado o campo versao
                'INSERT INTO pacientes (nome, nascimento, versao) VALUES (?, ?, 1)',
                (operado['nome'], operado['nascimento'])
            )
            paciente_id = cur.lastrowid

            # 2. Inserir consulta
            conn.execute(
                # Adicionado o campo versao
                'INSERT INTO consultas (paciente_id, data, escore, prioridade, versao) VALUES (?, ?, ?, ?, 1)',
                (paciente_id, operado['data_consulta'],
                 operado['escore'], operado['prioridade'])
            )

            # 3. Remover da tabela de operados
            conn.execute('DELETE FROM operados WHERE id = ?', (operado_id,))

            # Confirmar transação
            conn.execute("COMMIT")

            # Registrar atividade no log
            logger.info(
                f"Realização de cirurgia cancelada para paciente {operado['nome']} (ID: {operado_id})")

            flash(
                f"Paciente {operado['nome']} retornou à lista de espera.", "success")

    except Exception as e:
        # Em caso de erro, fazer rollback
        with get_db_connection() as conn:
            conn.execute("ROLLBACK")

        logger.error(f"Erro ao cancelar realização de cirurgia: {str(e)}")
        flash(f"Erro ao cancelar realização: {str(e)}", "error")

    return redirect(url_for('arquivo'))


@app.route('/marcar_demanda_judicial', methods=['POST'])
@login_required
def marcar_demanda_judicial():
    """Marca ou desmarca um paciente como demanda judicial"""
    if session['perfil'] not in ['medico', 'admin', 'gestor']:
        flash("Permissão negada", "error")
        return redirect(url_for('painel'))

    # Obter o ID do paciente e verificar se é para remover
    paciente_id = request.form.get('paciente_id')
    remover = request.form.get('remover') == 'true'

    if not paciente_id:
        flash("ID de paciente não fornecido", "error")
        return redirect(url_for('painel'))

    try:
        paciente_id = int(paciente_id)
    except (ValueError, TypeError):
        flash("ID de paciente inválido", "error")
        return redirect(url_for('painel'))

    try:
        with get_db_connection() as conn:
            # Verificar se o paciente existe
            paciente = conn.execute(
                'SELECT id, nome FROM pacientes WHERE id = ?', (paciente_id,)).fetchone()
            if not paciente:
                flash("Paciente não encontrado", "error")
                return redirect(url_for('painel'))

            # Obter a consulta mais recente
            conn.row_factory = sqlite3.Row  # Garantir que o resultado seja um dicionário
            ultima_consulta = conn.execute('''
                SELECT id, prioridade, escore, prioridade_anterior, escore_anterior, is_demanda_judicial
                FROM consultas 
                WHERE id = (
                    SELECT MAX(id) FROM consultas WHERE paciente_id = ?
                )
            ''', (paciente_id,)).fetchone()

            if not ultima_consulta:
                flash("Consulta não encontrada", "error")
                return redirect(url_for('painel'))

            conn.execute("BEGIN TRANSACTION")

            if remover:
                # Verificar debug para entender o problema
                logger.info(
                    f"Tentando remover status judicial. Valores: prioridade_anterior={ultima_consulta['prioridade_anterior']}, escore_anterior={ultima_consulta['escore_anterior']}")

                # Verificar se os valores anteriores existem
                if ultima_consulta['prioridade_anterior'] and ultima_consulta['escore_anterior']:
                    conn.execute('''
                        UPDATE consultas 
                        SET prioridade = ?, 
                            escore = ?,
                            data_judicial = NULL,
                            is_demanda_judicial = 0,
                            prioridade_anterior = NULL,
                            escore_anterior = NULL
                        WHERE id = ?
                    ''', (ultima_consulta['prioridade_anterior'],
                          ultima_consulta['escore_anterior'],
                          ultima_consulta['id']))

                    msg = f"Status de demanda judicial removido de {paciente['nome']}"
                    logger.info(msg)
                    flash(msg, "success")
                else:
                    # Se os valores anteriores não existirem, definir um valor padrão
                    conn.execute('''
                        UPDATE consultas 
                        SET prioridade = 'Prioridade Eletiva', 
                            escore = 5,
                            data_judicial = NULL,
                            is_demanda_judicial = 0,
                            prioridade_anterior = NULL,
                            escore_anterior = NULL
                        WHERE id = ?
                    ''', (ultima_consulta['id'],))

                    msg = f"Status de demanda judicial removido de {paciente['nome']} (valores originais não encontrados)"
                    logger.info(msg)
                    flash(msg, "warning")
            else:
                # Marcar como demanda judicial
                # Armazenar valores atuais antes de alterar
                data_atual = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                conn.execute('''
                    UPDATE consultas 
                    SET prioridade_anterior = prioridade,
                        escore_anterior = escore,
                        prioridade = 'Demanda Judicial', 
                        escore = 999,
                        data_judicial = ?,
                        is_demanda_judicial = 1
                    WHERE id = ?
                ''', (data_atual, ultima_consulta['id']))

                msg = f"Paciente {paciente['nome']} marcado como Demanda Judicial"
                logger.info(msg)
                flash(msg, "success")

            conn.execute("COMMIT")

            return redirect(url_for('painel'))

    except Exception as e:
        logger.error(f"Erro ao modificar status de demanda judicial: {str(e)}")
        # Log adicional para rastrear o erro
        logger.error(traceback.format_exc())
        flash(f"Erro ao processar: {str(e)}", "error")
        return redirect(url_for('painel'))


@app.route('/imprimir_lista_completa')
@login_required
def imprimir_lista_completa():
    try:
        pacientes = get_all_active_patients()
        # Calcula a posição na lista completa antes de passar para o template
        pacientes_com_posicao = []
        for index, paciente in enumerate(pacientes):
            paciente_dict = dict(paciente)  # Converte sqlite3.Row para dict
            paciente_dict['posicao'] = index + 1
            pacientes_com_posicao.append(paciente_dict)

        logger.info(
            f"Gerando lista completa para impressão com {len(pacientes_com_posicao)} pacientes.")
        return render_template('imprimir_lista.html', pacientes=pacientes_com_posicao)
    except Exception as e:
        logger.error(
            f"Erro ao gerar lista completa para impressão: {str(e)}\n{traceback.format_exc()}")
        flash("Erro ao gerar a lista para impressão.", "error")
        # Redireciona de volta ao painel em caso de erro
        return redirect(url_for('painel'))

# Add error handler


@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}\n{traceback.format_exc()}')
    return render_template('error.html'), 500


def init_db():
    """Inicializa o banco de dados"""
    try:
        with get_db_connection() as conn:
            # Verificar tabela pacientes
            columns_pacientes = conn.execute(
                "PRAGMA table_info(pacientes)").fetchall()
            column_names_pacientes = [col[1] for col in columns_pacientes]

            if 'versao' not in column_names_pacientes:
                conn.execute(
                    "ALTER TABLE pacientes ADD COLUMN versao INTEGER NOT NULL DEFAULT 1")

            # Verificar tabela consultas
            columns_consultas = conn.execute(
                "PRAGMA table_info(consultas)").fetchall()
            column_names_consultas = [col[1] for col in columns_consultas]

            if 'versao' not in column_names_consultas:
                conn.execute(
                    "ALTER TABLE consultas ADD COLUMN versao INTEGER NOT NULL DEFAULT 1")

            # Outras verificações existentes...
            if 'escore_anterior' not in column_names_consultas:
                conn.execute(
                    "ALTER TABLE consultas ADD COLUMN escore_anterior INTEGER")

            if 'prioridade_anterior' not in column_names_consultas:
                conn.execute(
                    "ALTER TABLE consultas ADD COLUMN prioridade_anterior TEXT")

            if 'is_demanda_judicial' not in column_names_consultas:
                conn.execute(
                    "ALTER TABLE consultas ADD COLUMN is_demanda_judicial INTEGER DEFAULT 0")

            if 'data_judicial' not in column_names_consultas:
                conn.execute(
                    "ALTER TABLE consultas ADD COLUMN data_judicial TEXT")

            # Verificar se o usuário admin já existe
            admin_exists = conn.execute(
                "SELECT COUNT(*) FROM usuarios WHERE usuario = 'admin'").fetchone()[0]

            # Se o usuário admin não existir, criá-lo
            if admin_exists == 0:
                logger.info("Criando usuário administrador padrão")
                senha_hash = generate_password_hash("Pedro123!")
                conn.execute("""
                    INSERT INTO usuarios (usuario, senha, perfil, senha_temporaria) 
                    VALUES (?, ?, ?, ?)
                """, ("admin", senha_hash, "admin", 0))
                conn.commit()
                logger.info("Usuário administrador padrão criado com sucesso")
    except Exception as e:
        logger.error(f"Erro ao inicializar banco de dados: {str(e)}")
        logger.error(traceback.format_exc())


if __name__ == '__main__':
    # Executar limpeza de arquivos temporários na inicialização
    with app.app_context():
        try:
            cleanup_temp_files()
            init_db()
        except Exception as e:
            logger.error(f"Erro na inicialização: {str(e)}")
            traceback.print_exc()

    # Alterado debug=True para debug=False para modo de produção
    app.run(host='0.0.0.0', port=5000, debug=False)
