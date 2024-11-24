using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Professores;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProfessoresController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public ProfessoresController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        [HttpPost]
        [Route("Register")]
        [SwaggerResponse(statusCode: 200, description: "Professores cadastrado com sucesso", Type = typeof(ProfessoresViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(ProfessoresViewModels))]
        public async Task<IActionResult> Register(ProfessoresViewModels model)
        {
            try
            {
                var professorExistente = await _unitOfWork.ProfessoresServices.ObterProfessoresUserId(model.UserId);
                if (professorExistente != null)
                {
                    return NotFound("Já existe um professores cadastrado com esse usuário.");
                }

                var professores = new EntidadeProfessores 
                {
                    UserId = model.UserId,
                    DataCadastro = DateTime.Now,
                    Foto = model.Foto,
                    Status = model.Status,
                    Cref = model.Cref,
                    Especialidade = model.Especialidade,
                    Cpf = model.Cpf,
                    Cep = model.Cep,
                    Endereco = model.Endereco,
                    Numero = model.Numero,
                    Bairro = model.Bairro,
                    Cidade = model.Cidade,
                    Estado = model.Estado,
                    DataNacimento = model.DataNacimento,

                };

                await _unitOfWork.ProfessoresServices.Cadastro(professores);
                await _unitOfWork.ProfessoresServices.Salvar();
                return Ok($"Professor cadastrados com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }
        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações do Professor obtidas com sucesso", typeof(ProfessoresUpdateViewModels))]
        [SwaggerResponse(404, "Professor não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var professoresComUsuarios = await _unitOfWork.ProfessoresServices.ObterProfessoresUsuariosPorId(id);

            if (professoresComUsuarios == null)
            {
                return NotFound("Professor não encontrado");
            }

            var professoresView = new ProfessoresUpdateViewModels
            {
                Id = professoresComUsuarios.Id,
                PrimeiroNome = professoresComUsuarios.User.PrimeiroNome,
                SobreNome = professoresComUsuarios.User.SobreNome,
                Email = professoresComUsuarios.User.Email,
                Cpf = professoresComUsuarios.Cpf,
                Cref = professoresComUsuarios.Cref,
                Especialidade = professoresComUsuarios.Especialidade,
                Cep = professoresComUsuarios.Cep,
                Endereco = professoresComUsuarios.Endereco,
                Numero = professoresComUsuarios.Numero,
                Bairro = professoresComUsuarios.Bairro,
                Cidade = professoresComUsuarios.Cidade,
                Estado = professoresComUsuarios.Estado,
                DataNacimento = professoresComUsuarios.DataNacimento,
            };

            return Ok(professoresView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Professor atualizado com sucesso", Type = typeof(ProfessoresViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Professor não encontrado", Type = typeof(ProfessoresViewModels))]
        public async Task<IActionResult> Update(ProfessoresUpdateViewModels model)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var professores = await _unitOfWork.ProfessoresServices.ObterPorId(model.Id);
                if (professores == null)
                {
                    return NotFound("Professores não encontrado");
                }

                var usuario = await _unitOfWork.UserServices.ObterPorUserId(professores.UserId);
                if (usuario == null)
                {
                    return NotFound("Usuário não encontrado");
                }

                usuario.PrimeiroNome = model.PrimeiroNome;
                usuario.SobreNome = model.SobreNome;
                usuario.Email = model.Email;
                professores.Cpf = model.Cpf;

                professores.Cep = model.Cep;
                professores.Endereco = model.Endereco;
                professores.Bairro = model.Bairro;
                professores.Numero = model.Numero;
                professores.Cidade = model.Cidade;
                professores.Estado = model.Estado;
                professores.DataNacimento = model.DataNacimento;

                await _unitOfWork.ProfessoresServices.Atualizar(professores);
                await _unitOfWork.UserServices.Atualizar(usuario);
                await _unitOfWork.ProfessoresServices.Salvar();

                return Ok($"Professor atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Professor excluído com sucesso")]
        [SwaggerResponse(404, "Professor não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var professor = await _unitOfWork.ProfessoresServices.ObterPorId(id);
                if (professor == null)
                {
                    return NotFound("Professor não encontrado");
                }

                await _unitOfWork.ProfessoresServices.Deletar(id);
                await _unitOfWork.ProfessoresServices.Salvar();

                return Ok("Professor excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }

    }
}
