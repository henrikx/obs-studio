use std::str::FromStr;

use anyhow::{bail, Result};
use log::{info, warn};
use reqwest::{
    header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE, LOCATION, USER_AGENT},
    Method, Url,
};
use webrtc::{
    ice_transport::{ice_credential_type::RTCIceCredentialType, ice_server::RTCIceServer},
    peer_connection::sdp::session_description::RTCSessionDescription,
};

use crate::obs_log;

const OBS_VERSION: &str = env!("OBS_VERSION");
const ROOT_DOMAIN: &'static str = "whip-edge.live-video.net";

#[derive(Debug)]
pub(crate) struct IceLink {
    uri: String,
    username: String,
    credential: String,
}

impl IceLink {
    pub(crate) fn parse(header: &str) -> Vec<IceLink> {
        header.split(',').map(IceLink::parse_link).collect::<_>()
    }

    fn parse_link(header: &str) -> Self {
        let mut components = header.split(';');
        let uri = components
            .next()
            .unwrap_or_default()
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>')
            .to_string();
        let _ = components
            .next()
            .unwrap_or_default()
            .trim()
            .trim_start_matches("rel=\"")
            .trim_end_matches('"')
            .to_string();
        let username = components
            .next()
            .unwrap_or_default()
            .trim()
            .trim_start_matches("username=\"")
            .trim_end_matches('"')
            .to_string();
        let credential = components
            .next()
            .unwrap_or_default()
            .trim()
            .trim_start_matches("credential=\"")
            .trim_end_matches('"')
            .to_string();

        IceLink {
            uri,
            username,
            credential,
        }
    }
}

pub async fn get_ice_credentials(
    participant_id: &str,
    bearer_token: Option<String>,
) -> Result<(Vec<webrtc::ice_transport::ice_server::RTCIceServer>, String)> {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(bearer_token) = bearer_token {
        let authoriation_value = HeaderValue::from_str(&format!("Bearer {bearer_token}"))?;
        headers.append(AUTHORIZATION, authoriation_value.clone());
    }

    let url = format!("https://miab.siobud.com/dataplane/publish/{participant_id}");

    // Handle redirects manually because auth header will be dropped
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    println!("Connecting to {:?} first", url);
    let mut next_url = reqwest::Url::from_str(&url)?;
    let response = loop {
        let request = reqwest::Request::new(Method::OPTIONS, next_url);
        let response = client.execute(request).await?;
        if response.status().is_redirection() {
            if let Some(location) = response.headers().get(HeaderName::from_static("location")) {
                let potential_next_url = reqwest::Url::from_str(location.to_str()?)?;
                if let Some(domain) = potential_next_url.domain() {
                    if !domain.ends_with(ROOT_DOMAIN) {
                        bail!("Invalid root domain: {domain}");
                    }
                    next_url = potential_next_url;
                } else {
                    bail!("Invalid root domain in redirect");
                }
                println!("Redirect! Next URL: {:?}", next_url);
                continue;
            }
            bail!("Uh.. no redirect location")
        } else {
            break response;
        }
    };

    if !response.status().is_success() {
        let t = response.text().await?;
        bail!("Invalid status: {:?}", t);
    }

    let link_headers = response.headers().get_all(reqwest::header::LINK);

    println!("{:?}", response.headers());
    let mut ice_servers = Vec::new();

    for l in link_headers {
        let links = IceLink::parse(l.to_str()?);

        for link in links {
            let ice_server = RTCIceServer {
                credential_type: RTCIceCredentialType::Password,
                username: link.username,
                credential: link.credential,
                urls: vec![link.uri],
            };

            ice_servers.push(ice_server);
        }
    }

    println!("Ice servers: {:?}", ice_servers);

    Ok((ice_servers, response.url().to_owned().to_string()))
}

pub async fn offer(
    url: &str,
    bearer_token: Option<String>,
    local_desc: RTCSessionDescription,
) -> Result<(RTCSessionDescription, Url)> {
    let client = reqwest::Client::new();

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/sdp"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&format!("libobs/{OBS_VERSION}"))?,
    );

    if let Some(bearer_token) = bearer_token {
        if !bearer_token.is_empty() {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {bearer_token}"))?,
            );
        }
    }

    if obs_log::debug_whip() {
        info!(
            "[WHIP DEBUG | CAUTION SENSITIVE INFO] Sending offer to {url}: {}",
            local_desc.sdp
        );
    }

    let request = client.post(url).headers(headers).body(local_desc.sdp);

    if obs_log::debug_whip() {
        info!("[WHIP DEBUG | CAUTION SENSITIVE INFO] Offer request {request:#?}");
    }

    let response = request.send().await?;

    if obs_log::debug_whip() {
        info!("[WHIP DEBUG | CAUTION SENSITIVE INFO] Offer response: {response:#?}");
    }

    let mut url = response.url().to_owned();
    if let Some(location) = response.headers().get(LOCATION) {
        url.set_path(location.to_str()?);
    }

    let body = response.text().await?;
    let sdp = RTCSessionDescription::answer(body)?;

    if obs_log::debug_whip() {
        info!("[WHIP DEBUG | CAUTION SENSITIVE INFO] Answer SDP: {sdp:#?}");
    }

    Ok((sdp, url))
}

pub async fn delete(url: &Url) -> Result<()> {
    let client = reqwest::Client::new();

    let request = client.delete(url.to_owned()).header(
        USER_AGENT,
        HeaderValue::from_str(&format!("libobs/{OBS_VERSION}"))?,
    );

    if obs_log::debug_whip() {
        info!("[WHIP DEBUG | CAUTION SENSITIVE INFO] Delete request {request:#?}");
    }

    let response = request.send().await?;

    if obs_log::debug_whip() {
        info!("[WHIP DEBUG | CAUTION SENSITIVE INFO] Delete response {response:#?}");
    }

    if !response.status().is_success() {
        warn!("Failed DELETE of whip resource: {}", response.status())
    }

    Ok(())
}
