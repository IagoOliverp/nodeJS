const express = require("express"); //Fazer a requisição da dependência EXPRESS do node
var cors = require('cors');

const bcrypt = require('bcryptjs') ;//Fazer a requisição da dependência bcryptjs para criptografia de senhas

const jwt = require("jsonwebtoken");

require('dotenv').config()

const {promisify} = require('util')

const {eAdmin} = require('./middlewares/auth')

const User = require('./models/User'); //Fazer a requisição da tabela Users do banco de dados
const { execArgv } = require("process");

const app = express(); //Atribuir à uma variável (app) a dependência (express)

app.use(express.json()); //Definir que o projeto utilize arquivos em formato JSON, no caso as "req" e "res"

app.use((req, res, next) => {
    res.header("Acess-Control-Allow-Origin", "*");
    res.header("Acess-Control-Allow-Methods", "GET, PUT, POST, DELETE");
    res.header("Acess-Control-Allow-Headers", "X-PINGOTHER, Content-Type, Authorization")
    app.use(cors());
    next();

});


/*app.use((req, res, next) =>{
    console.log("Middleware acessado");
    if (!req.body.nome) {
        return res.json({
            erro: true,
            mensagem: "Tente novamente, houve um erro no middleware"
        })
    }
    return next()
});*/

app.get("/users", eAdmin, async (req, res) => { //Rota para listar os dados do banco em formato JSON

    await User.findAll({
        attributes: ['id', 'name', 'email', 'password'],
        order: [['id','DESC']]})

    .then((users) => {
        return res.json({
            erro: false,
            users
        })
    }).catch(() => {
        return res.status(400).json({
            erro: true,
            mensagem: "Erro: Nenhum usuário encontrado!"
        });
    });
});

app.get("/user/:id", eAdmin, async (req, res) => { //Rota para listar o usuário do banco pelo ID no parâmetro HTTP
    const {id} = req.params;

    await User.findByPk(id)

    .then((user) => {
        return res.json({
            erro: false,
            user: user
        });
    }).catch(() => {
        return res.status(400).json({
            erro: true,
            mensagem: "Erro: Nenhum usuário encontrado!"
        });
    });
});

app.post("/user", eAdmin, async (req, res) => { //Rota para cadastrar usuário no banco de dados com senha criptografada utilizando a dependência (bcrypt)
    var dados = req.body;
    dados.password = await bcrypt.hash(dados.password, 8)

    await User.create(dados)
    then(() => {
        return res.json({
            erro: false,
            mensagem: "Usuário cadastrado com sucesso!"
        });
    }).catch(() => {
        return res.status(400).json({
            erro: true,
            mensagem: "Erro: Usuário não cadastrado com sucesso!"
        });
    });
});


app.put("/user", eAdmin, async (req, res) => { //Rota para editar atributos do usuário do banco através do ID
    const {id} = req.body;

    await User.update(req.body, {where: {id: id}})

    .then(() => {
        return res.json({
            erro: false,
            mensagem: "Usuário editado com sucesso!"
        });
    }).catch (() => {
        return res.status(400).json({
            erro: true,
            mensagem: "Erro: Usuário não editado com sucesso!"
        });
    });
});

app.put("/user-senha", eAdmin, async (req, res) => { //Rota para editar a senha do usuário do banco já criptografada
    const {id, password} = req.body;

    var senhaCrypt = await bcrypt.hash(password, 8);

    await User.update({password: senhaCrypt}, {where: {id}})

    .then(() => {
        return res.json({
            erro: false,
            mensagem: "Senha editada com sucesso!"
        });
    }).catch (() => {
        return res.status(400).json({
            erro: true,
            mensagem: "Erro: Senha não editada com sucesso!"
        });
    });
});

app.delete("/user/:id", eAdmin, async (req, res) => { //Rota para deletar o usuário do banco através do ID
    const {id} = req.params;

    await User.destroy({ where: {id}})

    .then(() => { 
        return res.json({
            erro: false,
            mensagem: "Usuário excluido com sucesso!"
        });
    }).catch(() => {
        return res.status(400).json({
            erro: true,
            mensagem: "Erro: Usuário não excluído com sucesso!"
        });
    });
});

app.post("/login", eAdmin, async (req, res) => { //Rota para logar pelo email e senha do usuário do banco com condições
    const user = await User.findOne({
        attributes: ['id', 'name', 'email', 'password'],
        where: {
            email: req.body.email
        }
    });

    if (user === null){
        return res.status(400).json({
            erro: true,
            mensagem: "Erro: Usuário ou senha incorreta!"
        });
    }

    if (!(await bcrypt.compare(req.body.password, user.password))){
        return res.status(400).json({
            erro: true,
            mensagem: "Erro: Usuário ou senha incorreta!"
        });
    };

    var token = jwt.sign({id: user.id, levelAcess: 1}, process.env.SECRET,{
        expiresIn: '7d' //7 dias
    });

    return res.json({
        erro: false,
        mensagem: "Login Realizado com Sucesso!",
        token
    });
});

app.get("/val-token", eAdmin, async (req, res) => {
    await User.findByPk(req.userId, {attributes: ['id', 'name', 'email']})
    .then((user) => {
        return res.json({
            erro: false,
            user
        });
    }).catch(() => {
        return res.status(401).json({
            erro: true,
            mensagem: "Erro: Necessário realizar o login para acessar a página"
        });

    });


    return res.json({
        erro: false,
        mensagem: "Token Válido!"
    });
});

app.listen(8080, () => { //Iniciar o app no servidor localhost da máquina com a porta: 8080
    console.log("Servidor iniciado na porta 8080: http://localhost:8080");

});