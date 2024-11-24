using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Enumerables;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Alunos;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AlunosController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public AlunosController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Aluno cadastrado com sucesso", Type = typeof(AlunosViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(AlunosViewModels))]
        public async Task<IActionResult> Register(AlunosViewModels model)
        {
            try
            {
                var alunoExistente = await _unitOfWork.AlunosServices.ObterAlunoPorUserId(model.UserId);
                if (alunoExistente != null)
                {
                    return NotFound("Já existe um aluno cadastrado com esse usuário.");
                }

                var alunos = new EntidadeAlunos
                {
                    UserId = model.UserId,
                    DataCadastro = DateTime.Now,
                    Foto = model.Foto,
                    Cpf = model.Cpf,
                    Cep = model.Cep,
                    Endereco = model.Endereco,
                    Numero = model.Numero,
                    Bairro = model.Bairro,
                    Cidade = model.Cidade,
                    Estado = model.Estado,
                    DataNacimento = model.DataNacimento,
                    StatusAlunos = StatusAlunosEnum.Pendente,

                };
                

                await _unitOfWork.AlunosServices.Cadastro(alunos);
                await _unitOfWork.AlunosServices.Salvar();
                return Ok($"Aluno cadastrado com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }
        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações do aluno obtidas com sucesso", typeof(AlunosUpdateViewModels))]
        [SwaggerResponse(404, "Aluno não encontrado")]
        public async Task<IActionResult> Update(int id)
         {
            var alunosComUsuarios = await _unitOfWork.AlunosServices.ObterAlunosUsuariosPorId(id);

            if (alunosComUsuarios == null)
            {
                return NotFound("Aluno não encontrado");
            }

            var alunosView = new AlunosUpdateViewModels
            {
                Id = alunosComUsuarios.Id,
                PrimeiroNome = alunosComUsuarios.User.PrimeiroNome,
                SobreNome = alunosComUsuarios.User.SobreNome,
                Email = alunosComUsuarios.User.Email,
                Cpf = alunosComUsuarios.Cpf,
                Cep = alunosComUsuarios.Cep,
                Endereco = alunosComUsuarios.Endereco,
                Numero = alunosComUsuarios.Numero,
                Bairro = alunosComUsuarios.Bairro,
                Cidade = alunosComUsuarios.Cidade,
                Estado = alunosComUsuarios.Estado,
                DataNacimento = alunosComUsuarios.DataNacimento,
            };

            return Ok(alunosView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Aluno atualizado com sucesso", Type = typeof(AlunosUpdateViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Aluno não encontrado", Type = typeof(AlunosUpdateViewModels))]
        public async Task<IActionResult> Update(AlunosUpdateViewModels model)
        {
            try
            {
                
                var alunos = await _unitOfWork.AlunosServices.ObterPorId(model.Id);
                if (alunos == null)
                {
                    return NotFound("Aluno não encontrado");
                }

                var usuario = await _unitOfWork.UserServices.ObterPorUserId(alunos.UserId);
                if (usuario == null)
                {
                    return NotFound("Usuário não encontrado");
                }

                usuario.PrimeiroNome = model.PrimeiroNome;
                usuario.SobreNome = model.SobreNome;
                usuario.Email = model.Email;
                alunos.Cpf = model.Cpf;
                alunos.Cep = model.Cep;
                alunos.Endereco = model.Endereco;
                alunos.Bairro = model.Bairro;
                alunos.Numero = model.Numero;
                alunos.Cidade = model.Cidade;
                alunos.Estado = model.Estado;
                alunos.DataNacimento = model.DataNacimento;

                await _unitOfWork.AlunosServices.Atualizar(alunos);
                await _unitOfWork.UserServices.Atualizar(usuario);
                await _unitOfWork.AlunosServices.Salvar();

                return Ok($"Aluno atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Aluno excluído com sucesso")]
        [SwaggerResponse(404, "Aluno não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var aluno = await _unitOfWork.AlunosServices.ObterPorId(id);
                if (aluno == null)
                {
                    return NotFound("Aluno não encontrado");
                }

                await _unitOfWork.AlunosServices.Deletar(id);
                await _unitOfWork.AlunosServices.Salvar();

                return Ok("Aluno excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpGet("BuscarUsuarios")]
        public async Task<IActionResult> BuscarUsuarios()
        {
            var resultado = await _unitOfWork.UserServices.ObterUsuariosComEmailConfirmado();
            if (resultado != null)
            {
                return Ok(resultado);
            }
            return NotFound();
        }

        [HttpGet("BuscarAlunosAtivos")]
        public async Task<IActionResult> BuscarAlunosAtivos()
        {

            var resultado = await _unitOfWork.AlunosServices.ObterAlunosAtivos();

            if (resultado != null)
            {
                return Ok(resultado.ToList());
            }
            return NotFound();

            

        }

    }
}
