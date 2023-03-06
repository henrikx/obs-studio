#pragma once

#include <string>

#include <obs.hpp>

struct WHIPService {
	std::string server;

	WHIPService(obs_data_t *settings, obs_service_t *service);

	void Update(obs_data_t *settings);
	static obs_properties_t *Properties();
	static void ApplyEncoderSettings(obs_data_t *video_settings,
					 obs_data_t *audio_settings);
};

void register_whip_service();
