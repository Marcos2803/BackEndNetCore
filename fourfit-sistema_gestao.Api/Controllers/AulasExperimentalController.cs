using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.AulaExperimental;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AulasExperimentalController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public AulasExperimentalController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }
        [HttpPost]
        [Route("Register")]
        //[Authorize]
        [SwaggerResponse(statusCode: 200, description: "Aula experimental agendada com sucesso", Type = typeof(AulaExperimentalViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(AulaExperimentalViewModels))]
        public async Task<IActionResult> Register(AulaExperimentalViewModels model)
        {
            try
            {
                var aulaExperimental = new AulaExperimental
                {
                    UserId = model.UserId,
                    DataHExperimental = DateTime.Now,
                    HorariosId = model.HorariosId,


                };

                await _unitOfWork.AulaExperimentalServices.Cadastro(aulaExperimental);
                await _unitOfWork.AulaExperimentalServices.Salvar();
                return Ok($"Aula Experimental agendada com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }



        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Aula experimental excluído com sucesso")]
        [SwaggerResponse(404, "Aula experimental não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var aulaexperimental = await _unitOfWork.AulaExperimentalServices.ObterPorId(id);
                if (aulaexperimental == null)
                {
                    return NotFound("Aula experimental não encontrado");
                }

                await _unitOfWork.AulaExperimentalServices.Deletar(id);
                await _unitOfWork.AulaExperimentalServices.Salvar();

                return Ok("Aula experimental excluída com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }

}

