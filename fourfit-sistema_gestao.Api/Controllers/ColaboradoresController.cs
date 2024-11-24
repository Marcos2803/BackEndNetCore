using fourfit.sistema_gestao.Domain.Entities.Profission;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Colaboradores;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ColaboradoresController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public ColaboradoresController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        [SwaggerResponse(statusCode: 200, description: "Colaboradores cadastrado com sucesso", Type = typeof(ColaboradoresViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(ColaboradoresViewModels))]
        public async Task<IActionResult> Register(ColaboradoresViewModels model)
        {
            try
            {
                var colaboradorExistente = await _unitOfWork.ColaboradoresServices.ObterColaboradorPorUserId(model.UserId);
                if (colaboradorExistente != null)
                {
                    return NotFound("Já existe um colaborador cadastrado com esse usuário.");
                }
                var colaboradores = new EntidadeColaboradores
                {
                    UserId = model.UserId,
                    DataCadastro = DateTime.Now,
                    Foto = model.Foto,
                    Status = model.Status,
                    Cpf = model.Cpf,
                    Cep = model.Cep,
                    Endereco = model.Endereco,
                    Numero = model.Numero,
                    Bairro = model.Bairro,
                    Cidade = model.Cidade,
                    Estado = model.Estado,
                    DataNacimento = model.DataNacimento,

                };

                await _unitOfWork.ColaboradoresServices.Cadastro(colaboradores);
                await _unitOfWork.ColaboradoresServices.Salvar();
                return Ok($"Colaborador cadastrados com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }
        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações do colaborador obtidas com sucesso", typeof(ColaboradoresUpdateViewModels))]
        [SwaggerResponse(404, "Colaborador não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var colaboradoresComUsuarios = await _unitOfWork.ColaboradoresServices.ObterColaboradoresUsuariosPorId(id);

            if (colaboradoresComUsuarios == null)
            {
                return NotFound("Colaborador não encontrado");
            }

            var colaboradoresView = new ColaboradoresUpdateViewModels
            {
                Id = colaboradoresComUsuarios.Id,
                PrimeiroNome = colaboradoresComUsuarios.User.PrimeiroNome,
                SobreNome = colaboradoresComUsuarios.User.SobreNome,
                Email = colaboradoresComUsuarios.User.Email,
                Cpf = colaboradoresComUsuarios.Cpf,
                Cep = colaboradoresComUsuarios.Cep,
                Endereco = colaboradoresComUsuarios.Endereco,
                Numero = colaboradoresComUsuarios.Numero,
                Bairro = colaboradoresComUsuarios.Bairro,
                Cidade = colaboradoresComUsuarios.Cidade,
                Estado = colaboradoresComUsuarios.Estado,
                DataNacimento = colaboradoresComUsuarios.DataNacimento,
            };

            return Ok(colaboradoresView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Colaborador atualizado com sucesso", Type = typeof(ColaboradoresUpdateViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Colaborador não encontrado", Type = typeof(ColaboradoresUpdateViewModels))]
        public async Task<IActionResult> Update(ColaboradoresUpdateViewModels model)
        {
            try
            {

                var colaboradores = await _unitOfWork.ColaboradoresServices.ObterPorId(model.Id);
                if (colaboradores == null)
                {
                    return NotFound("Aluno não encontrado");
                }

                var usuario = await _unitOfWork.UserServices.ObterPorUserId(colaboradores.UserId);
                if (usuario == null)
                {
                    return NotFound("Usuário não encontrado");
                }

                usuario.PrimeiroNome = model.PrimeiroNome;
                usuario.SobreNome = model.SobreNome;
                usuario.Email = model.Email;
                colaboradores.Cpf = model.Cpf;
                colaboradores.Cep = model.Cep;
                colaboradores.Endereco = model.Endereco;
                colaboradores.Bairro = model.Bairro;
                colaboradores.Numero = model.Numero;
                colaboradores.Cidade = model.Cidade;
                colaboradores.Estado = model.Estado;
                colaboradores.DataNacimento = model.DataNacimento;

                await _unitOfWork.ColaboradoresServices.Atualizar(colaboradores);
                await _unitOfWork.UserServices.Atualizar(usuario);
                await _unitOfWork.AlunosServices.Salvar();

                return Ok($"Colaborador atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Colaborador excluído com sucesso")]
        [SwaggerResponse(404, "Colaborador não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var colaborador = await _unitOfWork.ColaboradoresServices.ObterPorId(id);
                if (colaborador == null)
                {
                    return NotFound("Colaborador não encontrado");
                }

                await _unitOfWork.ColaboradoresServices.Deletar(id);
                await _unitOfWork.ColaboradoresServices.Salvar();

                return Ok("Colaborador excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }

    }
}

