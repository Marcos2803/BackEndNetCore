using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Checkin;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class CheckinsController : Controller
    {
        private readonly IUnitOfWork _unitOfWork;

        public CheckinsController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        [HttpPost]
        [Route("Register")]
        [SwaggerResponse(statusCode: 200, description: "chekins cadastrado com sucesso", Type = typeof(CheckinsViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(CheckinsViewModels))]
        public async Task<IActionResult> Register(CheckinsViewModels model)
        {
            try
            {
                var checkins = new Checkins
                {

                    DataCheckin = DateTime.Now,
                    AlunosId = model.AlunosId,
                    HorariosId = model.HorariosId,

                };

                await _unitOfWork.CheckinsServices.Cadastro(checkins);
                await _unitOfWork.CheckinsServices.Salvar();
                return Ok($"Checkin cadastrados com sucesso");
            }
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }
        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Checkin excluído com sucesso")]
        [SwaggerResponse(404, "Checkin não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var checkin = await _unitOfWork.CheckinsServices.ObterPorId(id);
                if (checkin == null)
                {
                    return NotFound("Checkin não encontrado");
                }

                await _unitOfWork.CheckinsServices.Deletar(id);
                await _unitOfWork.CheckinsServices.Salvar();

                return Ok("Checkin excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
