using fourfit.sistema_gestao.Domain.Entities.Alunos;
using fourfit.sistema_gestao.Domain.Enumerables;
using fourfit.sistema_gestao.Domain.Interfaces;
using fourfit_sistema_gestao.Api.Models.Alunos;
using fourfit_sistema_gestao.Api.Models.Horario;
using fourfit_sistema_gestao.Api.Validation;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace fourfit_sistema_gestao.Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HorariosController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;

        public HorariosController(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        [HttpPost]
        [Route("Register")]
        [SwaggerResponse(statusCode: 200, description: "Horarios cadastrado com sucesso", Type = typeof(HorariosViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Usuário nao autenticado", Type = typeof(HorariosViewModels))]
        public async Task<IActionResult> Register(HorariosViewModels model)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    TimeSpan horaInicio;
                    TimeSpan horaFim;

                    if (!TimeSpan.TryParse(model.HoraInicio, out horaInicio) || !TimeSpan.TryParse(model.HoraFim, out horaFim))
                    {
                        return BadRequest("HoraInicio ou HoraFim está em um formato inválido.");
                    }

                    var horarios = new Horarios
                    {
                        ProfessoresId = model.ProfessoresId,
                        ModalidadesId = model.ModalidadesId,
                        HoraInicio = TimeSpan.Parse(model.HoraInicio),
                        HoraFim = TimeSpan.Parse(model.HoraFim),
                        Status = model.Status,
                        Dia = model.Dia,
                        Descricao = model.Descricao,
                        LimiteAlunos = model.LimiteAlunos,

                    };

                    await _unitOfWork.HorariosServices.Cadastro(horarios);
                    await _unitOfWork.HorariosServices.Salvar();
                    return Ok($"Horarios cadastrados com sucesso");
                }
                else
                {
                    return BadRequest(ModelState);
                }

            }
             
            catch (Exception ex)
            {

                throw new Exception(ex.Message);
            }

        }

        [HttpGet]
        [Route("Update/{id}")]
        [SwaggerResponse(200, "Informações do aluno obtidas com sucesso", typeof(HorariosUpdateViewModels))]
        [SwaggerResponse(404, "Horario não encontrado")]
        public async Task<IActionResult> Update(int id)
        {
            var horariosId = await _unitOfWork.HorariosServices.ObterHorariosPorId(id);

            if (horariosId == null)
            {
                return NotFound("Horario não encontrado");
            }


            var horariosView = new HorariosUpdateViewModels
            {
                Id = horariosId.Id,
                ProfessoresId = horariosId.ProfessoresId,
                ModalidadesId = horariosId.ModalidadesId,
                Dia = horariosId.Dia,
                HoraInicio = horariosId.HoraInicio.ToString(@"hh\:mm"),  
                HoraFim = horariosId.HoraFim.ToString(@"hh\:mm"),
                Descricao = horariosId.Descricao,
                LimiteAlunos = horariosId.LimiteAlunos,
                Status = horariosId.Status,

            };

            return Ok(horariosView);
        }

        [HttpPut]
        [Route("Update")]
        [SwaggerResponse(statusCode: 200, description: "Horario atualizado com sucesso", Type = typeof(HorariosViewModels))]
        [SwaggerResponse(statusCode: 400, description: "Campos obrigatórios", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 500, description: "Erro internet", Type = typeof(ErrosGenericos))]
        [SwaggerResponse(statusCode: 401, description: "Não autorizado", Type = typeof(ValidarCampos))]
        [SwaggerResponse(statusCode: 404, description: "Horario não encontrado", Type = typeof(HorariosViewModels))]
        public async Task<IActionResult> Update(HorariosUpdateViewModels model)
        {
            try
            {

                var horarios = await _unitOfWork.HorariosServices.ObterPorId(model.Id);
                if (horarios == null)
                {
                    return NotFound("Horario não encontrado");
                }

                var modalidades = await _unitOfWork.ModalidadesServices.ObterModalidadesPorId(horarios.ModalidadesId);
                if (modalidades == null)
                {
                    return NotFound("Modalidade não encontrado");
                }

                var professores = await _unitOfWork.ProfessoresServices.ObterProfessoresUsuariosPorId(horarios.ProfessoresId);
                if (professores == null)
                {
                    return NotFound("Professor não encontrado");
                }

                if (!TimeSpan.TryParse(model.HoraInicio, out TimeSpan horaInicio) || !TimeSpan.TryParse(model.HoraFim, out TimeSpan horaFim))
                {
                    return BadRequest("HoraInicio ou HoraFim está em um formato inválido.");
                }

                horarios.ModalidadesId = model.ModalidadesId;
                horarios.ProfessoresId = model.ProfessoresId;
                horarios.Dia = model.Dia;
                horarios.HoraInicio = TimeSpan.Parse(model.HoraInicio);
                horarios.HoraFim = TimeSpan.Parse(model.HoraFim);
                horarios.Descricao = model.Descricao;
                horarios.LimiteAlunos = model.LimiteAlunos;
                horarios.Status = model.Status;
                
               
    

                await _unitOfWork.HorariosServices.Atualizar(horarios);
                await _unitOfWork.HorariosServices.Salvar();
               

                return Ok($"Horario atualizado com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }

        [HttpDelete]
        [Route("Delete/{id}")]
        [SwaggerResponse(200, "Horario excluído com sucesso")]
        [SwaggerResponse(404, "Horario não encontrado")]
        [SwaggerResponse(500, "Erro interno")]
        public async Task<IActionResult> Delete(int id)
        {
            try
            {
                var horario = await _unitOfWork.HorariosServices.ObterPorId(id);
                if (horario == null)
                {
                    return NotFound("Horario não encontrado");
                }

                await _unitOfWork.HorariosServices.Deletar(id);
                await _unitOfWork.HorariosServices.Salvar();

                return Ok("Horario excluído com sucesso");
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Erro interno: " + ex.Message);
            }
        }
    }
}
