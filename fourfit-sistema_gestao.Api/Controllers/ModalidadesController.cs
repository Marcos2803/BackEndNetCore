using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Alunos;
using fourfit_sistema_gestao.Api.Models.Modalidade;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ModalidadesController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public ModalidadesController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Modalidade cadastrado com sucesso", Type = typeof(ModalidadesViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(ModalidadesViewModels))]
        public async Task<IActionResult> Register(ModalidadesViewModels model)
        {
            try
            {
                var modalidades = new Modalidades
                {
                    Id = model.Id,
                    Nome = model.Nome,
                    PlanosId = model.PlanosId,
                    Descricao = model.Descricao,
                    Status = model.status,
                    AceitaCheckin = model.AceitaCheckin

                };

                await _unitOfWork.ModalidadesServices.Cadastro(modalidades);
                await _unitOfWork.ModalidadesServices.Salvar();
                return Ok($"Modalidade cadastrados com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações da modalidade obtidas com sucesso", typeof(ModalidadesUpdateViewModels))]
        [SwaggerResponse(404, "Mensalidade não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var modalidades = await _unitOfWork.ModalidadesServices.ObterModalidadesPorId(id);

            if (modalidades == null)
            {
                return NotFound("Modalidade não encontrado");
            }

            var modalidadesView = new ModalidadesUpdateViewModels
            {
                Id = modalidades.Id,
                Nome = modalidades.Nome,
                PlanosId = modalidades.PlanosId,
                Descricao = modalidades.Descricao,
                status = modalidades.Status,
                AceitaCheckin = modalidades.AceitaCheckin,

            };

            return Ok(modalidadesView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Modalidade atualizado com sucesso", Type = typeof(ModalidadesUpdateViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Modalidade não encontrado", Type = typeof(ModalidadesUpdateViewModels))]
        public async Task<IActionResult> Update(ModalidadesUpdateViewModels model)
        {
            try
            {

                var modalidades = await _unitOfWork.ModalidadesServices.ObterPorId(model.Id);
                if (modalidades == null)
                {
                    return NotFound("Modalidade não encontrado");
                }

                var plano = await _unitOfWork.TipoPlanoServices.ObterPlanosPorId(modalidades.PlanosId);
                if (plano == null)
                {
                    return NotFound("plano não encontrado");
                }

                modalidades.Nome = model.Nome;
                modalidades.PlanosId = model.PlanosId;
                modalidades.Descricao = model.Descricao;
                modalidades.Status = model.status;
                modalidades.AceitaCheckin = model.AceitaCheckin;

                await _unitOfWork.ModalidadesServices.Atualizar(modalidades);
                await _unitOfWork.ModalidadesServices.Salvar();

                return Ok($"Modalidade atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Modalidade excluído com sucesso")]
        [SwaggerResponse(404, "Modalidade não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var modalidade = await _unitOfWork.ModalidadesServices.ObterPorId(id);
                if (modalidade == null)
                {
                    return NotFound("Modalidade não encontrado");
                }

                await _unitOfWork.ModalidadesServices.Deletar(id);
                await _unitOfWork.ModalidadesServices.Salvar();

                return Ok("Modalidade excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }

    }
}
